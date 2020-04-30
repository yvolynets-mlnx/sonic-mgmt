import pytest
import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet
import logging
import importlib
import pprint
import random
import time
import scapy
import yaml
import re
import os
import json
import netaddr


logger = logging.getLogger(__name__)

PKT_NUMBER = 1000

# Discard key from 'portstat -j' CLI command output
RX_DRP = "RX_DRP"
RX_ERR = "RX_ERR"
# CLI commands to obtain drop counters
GET_L2_COUNTERS = "portstat -j"
GET_L3_COUNTERS = "intfstat -j"
ACL_COUNTERS_UPDATE_INTERVAL = 10
LOG_EXPECT_ACL_RULE_CREATE_RE = ".*Successfully created ACL rule.*"
LOG_EXPECT_ACL_RULE_REMOVE_RE = ".*Successfully deleted ACL rule.*"
LOG_EXPECT_PORT_ADMIN_DOWN_RE = ".*Configure {} admin status to down.*"
LOG_EXPECT_PORT_ADMIN_UP_RE = ".*Port {} oper state set from down to up.*"

COMBINED_L2L3_DROP_COUNTER = False
COMBINED_ACL_DROP_COUNTER = False


def parse_combined_counters(duthost):
    # Get info whether L2 and L3 drop counters are linked
    # Or ACL and L2 drop counters are linked
    global COMBINED_L2L3_DROP_COUNTER, COMBINED_ACL_DROP_COUNTER
    base_dir = os.path.dirname(os.path.realpath(__file__))
    with open(os.path.join(base_dir, "combined_drop_counters.yml")) as stream:
        regexps = yaml.safe_load(stream)
        if regexps["l2_l3"]:
            for item in regexps["l2_l3"]:
                if re.match(item, duthost.facts["platform"]):
                    COMBINED_L2L3_DROP_COUNTER = True
                    break
        if regexps["acl_l2"]:
            for item in regexps["acl_l2"]:
                if re.match(item, duthost.facts["platform"]):
                    COMBINED_ACL_DROP_COUNTER = True
                    break

MELLANOX_MAC_UPDATE_SCRIPT = os.path.join(os.path.dirname(__file__), "fanout/mellanox/mlnx_update_mac.j2")


@pytest.fixture(scope="module")
def pkt_fields(duthost):
    # Gather ansible facts
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    ipv4_addr = None
    ipv6_addr = None

    for item in mg_facts["minigraph_bgp"]:
        if item["name"] == mg_facts["minigraph_bgp"][0]["name"]:
            if netaddr.valid_ipv4(item["addr"]):
                ipv4_addr = item["addr"]
            else:
                ipv6_addr = item["addr"]

    class Collector(dict):
        def __getitem__(self, key):
            value = super(Collector, self).__getitem__(key)
            if key == "ipv4_dst" and value is None:
                pytest.skip("IPv4 address is not defined")
            elif key == "ipv6_dst" and value is None:
                pytest.skip("IPv6 address is not defined")
            return value

    test_pkt_data = Collector({
        "ipv4_dst": ipv4_addr,
        "ipv4_src": "1.1.1.1",
        "ipv6_dst": ipv6_addr,
        "ipv6_src": "ffff::101:101",
        "tcp_sport": 1234,
        "tcp_dport": 4321
        })
    return test_pkt_data


@pytest.fixture(scope="module")
def setup(duthost, testbed):
    """
    Setup fixture for collecting PortChannel, VLAN and RIF port members.
    @return: Dictionary with keys:
        port_channel_members, vlan_members, rif_members, dut_to_ptf_port_map, neighbor_sniff_ports, vlans, mg_facts
    """
    port_channel_members = {}
    vlan_members = {}
    configured_vlans = []
    rif_members = []

    if testbed["topo"] == "ptf32":
        pytest.skip("Unsupported topology {}".format(testbed["topo"]))

    # Gather ansible facts
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']

    for port_channel, interfaces in mg_facts['minigraph_portchannels'].items():
        for iface in interfaces["members"]:
            port_channel_members[iface] = port_channel

    for vlan_id in mg_facts["minigraph_vlans"]:
        for iface in mg_facts["minigraph_vlans"][vlan_id]["members"]:
            vlan_members[iface] = vlan_id

    rif_members = {item["attachto"]: item["attachto"] for item in mg_facts["minigraph_interfaces"]}

    # Compose list of sniff ports
    neighbor_sniff_ports = []
    for dut_port, neigh in mg_facts['minigraph_neighbors'].items():
        neighbor_sniff_ports.append(mg_facts['minigraph_port_indices'][dut_port])

    for vlan_name, vlans_data in mg_facts["minigraph_vlans"].items():
        configured_vlans.append(int(vlans_data["vlanid"]))

    setup_information = {
        "port_channel_members": port_channel_members,
        "vlan_members": vlan_members,
        "rif_members": rif_members,
        "dut_to_ptf_port_map": mg_facts["minigraph_port_indices"],
        "neighbor_sniff_ports": neighbor_sniff_ports,
        "vlans": configured_vlans,
        "mg_facts": mg_facts
    }
    parse_combined_counters(duthost)
    return setup_information


@pytest.fixture(params=["port_channel_members", "vlan_members", "rif_members"])
def tx_dut_ports(request, setup):
    """ Fixture for getting port members of specific port group """
    return setup[request.param] if setup[request.param] else pytest.skip("No {} available".format(request.param))


@pytest.fixture(autouse=True, scope="module")
def enable_counters(duthost):
    """ Fixture which enables RIF and L2 counters """
    cmd_list = ["intfstat -D", "counterpoll port enable", "counterpoll rif enable", "sonic-clear counters",
                "sonic-clear rifcounters"]
    cmd_get_cnt_status = "redis-cli -n 4 HGET \"FLEX_COUNTER_TABLE|{}\" \"FLEX_COUNTER_STATUS\""

    previous_cnt_status = {item: duthost.command(cmd_get_cnt_status.format(item.upper()))["stdout"] for item in ["port", "rif"]}

    for cmd in cmd_list:
        duthost.command(cmd)
    yield
    for port, status in previous_cnt_status.items():
        if status == "disable":
            logger.info("Restoring counter '{}' state to disable".format(port))
            duthost.command("counterpoll {} disable".format(port))


@pytest.fixture
def mtu_config(duthost):
    """ Fixture which prepare port MTU configuration for 'test_ip_pkt_with_exceeded_mtu' test case """
    class MTUConfig(object):
        iface = None
        mtu = None
        default_mtu = 9100
        @classmethod
        def set_mtu(cls, mtu, iface):
            cls.mtu = duthost.command("redis-cli -n 4 hget \"PORTCHANNEL|{}\" mtu".format(iface))["stdout"]
            if not cls.mtu:
                cls.mtu = cls.default_mtu
            if "PortChannel" in iface:
                duthost.command("redis-cli -n 4 hset \"PORTCHANNEL|{}\" mtu {}".format(iface, mtu))["stdout"]
            elif "Ethernet" in iface:
                duthost.command("redis-cli -n 4 hset \"PORT|{}\" mtu {}".format(iface, mtu))["stdout"]
            else:
                raise Exception("Unsupported interface parameter - {}".format(iface))
            cls.iface = iface
        @classmethod
        def restore_mtu(cls):
            if cls.iface:
                if "PortChannel" in cls.iface:
                    duthost.command("redis-cli -n 4 hset \"PORTCHANNEL|{}\" mtu {}".format(cls.iface, cls.mtu))["stdout"]
                elif "Ethernet" in cls.iface:
                    duthost.command("redis-cli -n 4 hset \"PORT|{}\" mtu {}".format(cls.iface, cls.mtu))["stdout"]
                else:
                    raise Exception("Trying to restore MTU on unsupported interface - {}".format(cls.iface))

    yield MTUConfig

    MTUConfig.restore_mtu()


@pytest.fixture
def acl_setup(duthost, loganalyzer):
    """ Create acl rule defined in config file. Delete rule after test case finished """
    base_dir = os.path.dirname(os.path.realpath(__file__))
    template_dir = os.path.join(base_dir, 'acl_templates')
    acl_rules_template = "acltb_test_rule.json"
    del_acl_rules_template = "acl_rule_del.json"
    dut_tmp_dir = os.path.join("tmp", os.path.basename(base_dir))

    duthost.command("mkdir -p {}".format(dut_tmp_dir))
    dut_conf_file_path = os.path.join(dut_tmp_dir, acl_rules_template)
    dut_clear_conf_file_path = os.path.join(dut_tmp_dir, del_acl_rules_template)

    logger.info("Generating config for ACL rule, ACL table - DATAACL")
    duthost.template(src=os.path.join(template_dir, acl_rules_template), dest=dut_conf_file_path)
    logger.info("Generating clear config for ACL rule, ACL table - DATAACL")
    duthost.template(src=os.path.join(template_dir, del_acl_rules_template), dest=dut_clear_conf_file_path)

    logger.info("Applying {}".format(dut_conf_file_path))

    loganalyzer.expect_regex = [LOG_EXPECT_ACL_RULE_CREATE_RE]
    with loganalyzer as analyzer:
        duthost.command("config acl update full {}".format(dut_conf_file_path))

    yield

    loganalyzer.expect_regex = [LOG_EXPECT_ACL_RULE_REMOVE_RE]
    with loganalyzer as analyzer:
        logger.info("Applying {}".format(dut_clear_conf_file_path))
        duthost.command("config acl update full {}".format(dut_clear_conf_file_path))
        logger.info("Removing {}".format(dut_tmp_dir))
        duthost.command("rm -rf {}".format(dut_tmp_dir))


@pytest.fixture
def rif_port_down(duthost, setup, loganalyzer):
    """ Disable RIF interface and return neighbor IP address attached to this interface """
    wait_after_ports_up = 30

    if not setup["rif_members"]:
        pytest.skip("RIF interface is absent")
    rif_member_iface = setup["rif_members"].keys()[0]

    try:
        vm_name = setup["mg_facts"]["minigraph_neighbors"][rif_member_iface]["name"]
    except KeyError as err:
        pytest.fail("Didn't found RIF interface in 'minigraph_neighbors'. {}".format(str(err)))

    ip_dst = None
    for item in setup["mg_facts"]["minigraph_bgp"]:
        if item["name"] == vm_name:
            if netaddr.valid_ipv4(item["addr"]):
                ip_dst = item["addr"]
                break
    else:
        pytest.fail("Unable to find neighbor in 'minigraph_bgp' list")

    loganalyzer.expect_regex = [LOG_EXPECT_PORT_ADMIN_DOWN_RE.format(rif_member_iface)]
    with loganalyzer as analyzer:
        duthost.command("config interface shutdown {}".format(rif_member_iface))

    time.sleep(1)

    yield ip_dst

    loganalyzer.expect_regex = [LOG_EXPECT_PORT_ADMIN_UP_RE.format(rif_member_iface)]
    with loganalyzer as analyzer:
        duthost.command("config interface startup {}".format(rif_member_iface))
        time.sleep(wait_after_ports_up)


@pytest.fixture
def fanouthost(request, testbed_devices):
    """
    Fixture that allows to update Fanout configuration if there is a need to send incorrect packets.
    Added possibility to create vendor specific logic to handle fanout configuration.
    If vendor need to update Fanout configuration, 'fanouthost' fixture should load and return appropriate instance.
    This instance can be used inside test case to handle fanout configuration in vendor specific section.
    By default 'fanouthost' fixture will not instantiate any instance so it will return None, and in such case
    'fanouthost' instance should not be used in test case logic.
    """
    dut = testbed_devices["dut"]
    fanout = None
    # Check that class to handle fanout config is implemented
    if "mellanox" == dut.facts["asic_type"]:
        for file_name in os.listdir(os.path.join(os.path.dirname(__file__), "fanout")):
            # Import fanout configuration handler based on vendor name
            if "mellanox" in file_name:
                module = importlib.import_module("fanout.{0}.{0}_fanout".format(file_name.strip(".py")))
                fanout = module.FanoutHandler(testbed_devices)
                break

    yield fanout

    if fanout is not None:
        fanout.restore_config()


def get_pkt_drops(duthost, cli_cmd):
    """
    @summary: Parse output of "portstat" or "intfstat" commands and convert it to the dictionary.
    @param module: The AnsibleModule object
    @param cli_cmd: one of supported CLI commands - "portstat -j" or "intfstat -j"
    @return: Return dictionary of parsed counters
    """
    stdout = duthost.command(cli_cmd)
    if stdout["rc"] != 0:
        raise Exception(stdout["stdout"] + stdout["stderr"])
    stdout = stdout["stdout"]

    match = re.search("Last cached time was.*\n", stdout)
    if match:
        stdout = re.sub("Last cached time was.*\n", "", stdout)

    try:
        return json.loads(stdout)
    except Exception as err:
        raise Exception("Failed to parse output of '{}', err={}".format(cli_cmd, str(err)))


def get_dut_iface_mac(duthost, iface_name):
    """ Fixture for getting MAC address of specified interface """
    for iface, iface_info in duthost.setup()['ansible_facts'].items():
        if iface_name in iface:
            return iface_info["macaddress"]


@pytest.fixture
def ports_info(ptfadapter, duthost, setup, tx_dut_ports):
    """
    Return:
        dut_iface - DUT interface name expected to receive packtes from PTF
        ptf_tx_port_id - Port ID used by PTF for sending packets from expected PTF interface
        dst_mac - DUT interface destination MAC address
        src_mac - PTF interface source MAC address
    """
    data = {}
    data["dut_iface"] = random.choice(tx_dut_ports.keys())
    data["ptf_tx_port_id"] = setup["dut_to_ptf_port_map"][data["dut_iface"]]
    data["dst_mac"] = get_dut_iface_mac(duthost, data["dut_iface"])
    data["src_mac"] = ptfadapter.dataplane.ports[(0, data["ptf_tx_port_id"])].mac()
    return data


def expected_packet_mask(pkt):
    """ Return mask for sniffing packet """

    exp_pkt = pkt.copy()
    exp_pkt = mask.Mask(exp_pkt)
    exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
    exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
    exp_pkt.set_do_not_care_scapy(packet.IP, 'ttl')
    exp_pkt.set_do_not_care_scapy(packet.IP, 'chksum')
    return exp_pkt


def log_pkt_params(dut_iface, mac_dst, mac_src, ip_dst, ip_src):
    """ Displays information about packet fields used in test case: mac_dst, mac_src, ip_dst, ip_src """
    logger.info("Selected TX interface on DUT - {}".format(dut_iface))
    logger.info("Packet DST MAC - {}".format(mac_dst))
    logger.info("Packet SRC MAC - {}".format(mac_src))
    logger.info("Packet IP DST - {}".format(ip_dst))
    logger.info("Packet IP SRC - {}".format(ip_src))


def ensure_no_l3_drops(duthost):
    """ Verify L3 drop counters were not incremented """
    intf_l3_counters = get_pkt_drops(duthost, GET_L3_COUNTERS)
    unexpected_drops = {}
    for iface, value in intf_l3_counters.items():
        try:
            rx_err_value = int(value[RX_ERR])
        except ValueError as err:
            logger.warning("Unable to verify L3 drops on iface {}\n{}".format(iface, err))
            continue
        if rx_err_value >= PKT_NUMBER:
            unexpected_drops[iface] = rx_err_value
    if unexpected_drops:
        pytest.fail("L3 'RX_ERR' was incremented for the following interfaces:\n{}".format(unexpected_drops))


def ensure_no_l2_drops(duthost):
    """ Verify L2 drop counters were not incremented """
    intf_l2_counters = get_pkt_drops(duthost, GET_L2_COUNTERS)
    unexpected_drops = {}
    for iface, value in intf_l2_counters.items():
        try:
            rx_drp_value = int(value[RX_DRP])
        except ValueError as err:
            logger.warning("Unable to verify L2 drops on iface {}\n{}".format(iface, err))
            continue
        if rx_drp_value >= PKT_NUMBER:
            unexpected_drops[iface] = rx_drp_value
    if unexpected_drops:
        pytest.fail("L2 'RX_DRP' was incremented for the following interfaces:\n{}".format(unexpected_drops))


def send_packets(pkt, duthost, ptfadapter, ptf_tx_port_id):
    # Clear SONiC counters
    duthost.command("sonic-clear counters")
    duthost.command("sonic-clear rifcounters")

    # Clear packets buffer on PTF
    ptfadapter.dataplane.flush()
    time.sleep(1)

    # Send packets
    testutils.send(ptfadapter, ptf_tx_port_id, pkt, count=PKT_NUMBER)
    time.sleep(1)


def str_to_int(value):
    """ Convert string value which can contain ',' symbols to integer value """
    return int(value.replace(",", ""))


def verify_drop_counters(duthost, dut_iface, get_cnt_cli_cmd, column_key):
    """ Verify drop counter incremented on specific interface """
    drops = get_pkt_drops(duthost, get_cnt_cli_cmd)[dut_iface][column_key]
    drops = str_to_int(drops)

    if drops != PKT_NUMBER:
        fail_msg = "'{}' drop counter was not incremented on iface {}. DUT {} == {}; Sent == {}".format(
            column_key, dut_iface, column_key, drops, PKT_NUMBER
        )
        pytest.fail(fail_msg)


def base_verification(discard_group, pkt, ptfadapter, duthost, ptf_tx_port_id, dut_iface, l2_col_key=RX_DRP, l3_col_key=RX_ERR):
    """
    Base test function for verification of L2 or L3 packet drops. Verification type depends on 'discard_group' value.
    Supported 'discard_group' values: 'L2', 'L3', 'ACL'
    """
    send_packets(pkt, duthost, ptfadapter, ptf_tx_port_id)
    if discard_group == "L2":
        verify_drop_counters(duthost, dut_iface, GET_L2_COUNTERS, l2_col_key)
        ensure_no_l3_drops(duthost)
    elif discard_group == "L3":
        if COMBINED_L2L3_DROP_COUNTER:
            verify_drop_counters(duthost, dut_iface, GET_L2_COUNTERS, l2_col_key)
            ensure_no_l3_drops(duthost)
        else:
            verify_drop_counters(duthost, dut_iface, GET_L3_COUNTERS, l3_col_key)
            ensure_no_l2_drops(duthost)
    elif discard_group == "ACL":
        time.sleep(ACL_COUNTERS_UPDATE_INTERVAL)
        acl_drops = duthost.acl_facts()["ansible_facts"]["ansible_acl_facts"]["DATAACL"]["rules"]["RULE_1"]["packets_count"]
        if acl_drops != PKT_NUMBER:
            fail_msg = "ACL drop counter was not incremented on iface {}. DUT ACL counter == {}; Sent pkts == {}".format(
                dut_iface, acl_drops, PKT_NUMBER
            )
            pytest.fail(fail_msg)
        if not COMBINED_ACL_DROP_COUNTER:
            ensure_no_l3_drops(duthost)
            ensure_no_l2_drops(duthost)
    else:
        pytest.fail("Incorrect 'discard_group' specified. Supported values: 'L2' or 'L3'")


def do_test(discard_group, pkt, ptfadapter, duthost, ptf_tx_port_id, dut_iface, sniff_ports, l2_col_key=RX_DRP, l3_col_key=RX_ERR):
    """
    Execute test - send packet, check that expected discard counters were incremented and packet was dropped
    @param discard_group: Supported 'discard_group' values: 'L2', 'L3', 'ACL'
    @param pkt: PTF composed packet, sent by test case
    @param ptfadapter: fixture
    @param duthost: fixture
    @param ptf_tx_port_id: TX PTF port ID
    @param dut_iface: DUT interface name expected to receive packets from PTF
    @param sniff_ports: DUT ports to check that packets were not egressed from
    """
    base_verification(discard_group, pkt, ptfadapter, duthost, ptf_tx_port_id, dut_iface, l2_col_key, l3_col_key)

    # Verify packets were not egresed the DUT
    exp_pkt = expected_packet_mask(pkt)
    testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=sniff_ports)


def test_equal_smac_dmac_drop(ptfadapter, duthost, setup, fanouthost, pkt_fields, ports_info):
    """
    @summary: Verify that packet with equal SMAC and DMAC is dropped and L2 drop counter incremented
    """
    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["dst_mac"], pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])
    src_mac = ports_info["dst_mac"]

    if "mellanox" == duthost.facts["asic_type"]:
        pytest.skip("Currently not supported on Mellanox platform")
        src_mac = "00:00:00:00:00:11"
        # Prepare openflow rule
        fanouthost.update_config(template_path=MELLANOX_MAC_UPDATE_SCRIPT, match_mac=src_mac, set_mac=ports_info["dst_mac"], eth_field="eth_src")

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"], # DUT port
        eth_src=src_mac, # PTF port
        ip_src=pkt_fields["ipv4_src"], # PTF source
        ip_dst=pkt_fields["ipv4_dst"], # VM source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"])

    do_test("L2", pkt, ptfadapter, duthost, ports_info["ptf_tx_port_id"], ports_info["dut_iface"], setup["neighbor_sniff_ports"])


def test_multicast_smac_drop(ptfadapter, duthost, setup, fanouthost, pkt_fields, ports_info):
    """
    @summary: Verify that packet with multicast SMAC is dropped and L2 drop counter incremented
    """
    multicast_smac = "01:00:5e:00:01:02"
    src_mac = multicast_smac

    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], multicast_smac, pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])

    if "mellanox" == duthost.facts["asic_type"]:
        pytest.skip("Currently not supported on Mellanox platform")
        src_mac = "00:00:00:00:00:11"
        # Prepare openflow rule
        fanouthost.update_config(template_path=MELLANOX_MAC_UPDATE_SCRIPT, match_mac=src_mac, set_mac=multicast_smac, eth_field="eth_src")

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"], # DUT port
        eth_src=src_mac,
        ip_src=pkt_fields["ipv4_src"], # PTF source
        ip_dst=pkt_fields["ipv4_dst"], # VM source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"])

    do_test("L2", pkt, ptfadapter, duthost, ports_info["ptf_tx_port_id"], ports_info["dut_iface"], setup["neighbor_sniff_ports"])


def test_reserved_dmac_drop(ptfadapter, duthost, setup, fanouthost, pkt_fields, ports_info):
    """
    @summary: Verify that packet with reserved DMAC is dropped and L2 drop counter incremented
    @used_mac_address:
        01:80:C2:00:00:05 - reserved for future standardization
        01:80:C2:00:00:08 - provider Bridge group address
    """
    reserved_mac_addr = ["01:80:C2:00:00:05", "01:80:C2:00:00:08"]

    for reserved_dmac in reserved_mac_addr:
        dst_mac = reserved_dmac
        if "mellanox" == duthost.facts["asic_type"]:
            pytest.skip("Currently not supported on Mellanox platform")
            dst_mac = "00:00:00:00:00:11"
            # Prepare openflow rule
            fanouthost.update_config(template_path=MELLANOX_MAC_UPDATE_SCRIPT, match_mac=dst_mac, set_mac=reserved_dmac, eth_field="eth_dst")

        log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], reserved_dmac, pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])
        pkt = testutils.simple_tcp_packet(
            eth_dst=dst_mac, # DUT port
            eth_src=ports_info["src_mac"],
            ip_src=pkt_fields["ipv4_src"], # PTF source
            ip_dst=pkt_fields["ipv4_dst"], # VM source
            tcp_sport=pkt_fields["tcp_sport"],
            tcp_dport=pkt_fields["tcp_dport"])

        do_test("L2", pkt, ptfadapter, duthost, ports_info["ptf_tx_port_id"], ports_info["dut_iface"], setup["neighbor_sniff_ports"])


def test_not_expected_vlan_tag_drop(ptfadapter, duthost, setup, pkt_fields, ports_info):
    """
    @summary: Verify that VLAN tagged packet which VLAN ID does not match ingress port VLAN ID is dropped
              and L2 drop counter incremented
    """
    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"], pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])
    max_vlan_id = 1000
    upper_bound = max(setup["vlans"]) if setup["vlans"] else max_vlan_id
    for interim in range(1, upper_bound):
        if interim not in setup["vlans"]:
            vlan_id = interim
            break
    else:
        pytest.fail("Unable to generate unique not yet existed VLAN ID. Already configured VLANs range {}-{}".format(1, upper_bound))

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"], # DUT port
        eth_src=ports_info["src_mac"], # PTF port
        ip_src=pkt_fields["ipv4_src"], # PTF source
        ip_dst=pkt_fields["ipv4_dst"], # VM source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"],
        dl_vlan_enable=True,
        vlan_vid=vlan_id,
        )

    do_test("L2", pkt, ptfadapter, duthost, ports_info["ptf_tx_port_id"], ports_info["dut_iface"], setup["neighbor_sniff_ports"])


def test_dst_ip_is_loopback_addr(ptfadapter, duthost, setup, pkt_fields, tx_dut_ports, ports_info):
    """
    @summary: Verify that packet with loopback destination IP adress is dropped and L3 drop counter incremented
    """
    ip_dst = "127.0.0.1"

    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"], ip_dst, pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"], # DUT port
        eth_src=ports_info["src_mac"], # PTF port
        ip_src=pkt_fields["ipv4_src"], # PTF source
        ip_dst=ip_dst, # VM source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"])

    do_test("L3", pkt, ptfadapter, duthost, ports_info["ptf_tx_port_id"], tx_dut_ports[ports_info["dut_iface"]], setup["neighbor_sniff_ports"])


def test_src_ip_is_loopback_addr(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, ports_info):
    """
    @summary: Verify that packet with loopback source IP adress is dropped and L3 drop counter incremented
    """
    ip_src = "127.0.0.1"

    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"], pkt_fields["ipv4_dst"], ip_src)

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"], # DUT port
        eth_src=ports_info["src_mac"], # PTF port
        ip_src=ip_src, # PTF source
        ip_dst=pkt_fields["ipv4_dst"], # VM source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"])

    do_test("L3", pkt, ptfadapter, duthost, ports_info["ptf_tx_port_id"], tx_dut_ports[ports_info["dut_iface"]], setup["neighbor_sniff_ports"])


def test_dst_ip_absent(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, ports_info):
    """
    @summary: Verify that packet with absent destination IP address is dropped and L3 drop counter incremented
    """
    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"], "", pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"], # DUT port
        eth_src=ports_info["src_mac"], # PTF port
        ip_src=pkt_fields["ipv4_src"], # PTF source
        ip_dst="", # VM source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"])
    do_test("L3", pkt, ptfadapter, duthost, ports_info["ptf_tx_port_id"], tx_dut_ports[ports_info["dut_iface"]], setup["neighbor_sniff_ports"])


@pytest.mark.parametrize("ip_addr", ["ipv4", "ipv6"])
def test_src_ip_is_multicast_addr(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, ip_addr, ports_info):
    """
    @summary: Verify that packet with multicast source IP adress is dropped and L3 drop counter incremented
    """
    ip_src = None

    if ip_addr == "ipv4":
        ip_src = "224.0.0.5"
        pkt = testutils.simple_tcp_packet(
            eth_dst=ports_info["dst_mac"], # DUT port
            eth_src=ports_info["src_mac"], # PTF port
            ip_src=ip_src,
            ip_dst=pkt_fields["ipv4_dst"], # VM source
            tcp_sport=pkt_fields["tcp_sport"],
            tcp_dport=pkt_fields["tcp_dport"])
    elif ip_addr == "ipv6":
        if not pkt_fields["ipv6_dst"]:
            pytest.skip("BGP neighbour with IPv6 addr was not found")
        ip_src = "FF02:AAAA:FEE5::1:3"
        pkt = testutils.simple_tcpv6_packet(
            eth_dst=ports_info["dst_mac"], # DUT port
            eth_src=ports_info["src_mac"], # PTF port
            ipv6_src=ip_src,
            ipv6_dst=pkt_fields["ipv6_dst"], # VM source
            tcp_sport=pkt_fields["tcp_sport"],
            tcp_dport=pkt_fields["tcp_dport"])
    else:
        pytest.fail("Incorrect value specified for 'ip_addr' test parameter. Supported parameters: 'ipv4' and 'ipv6'")

    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"], pkt_fields["ipv4_dst"], ip_src)
    do_test("L3", pkt, ptfadapter, duthost, ports_info["ptf_tx_port_id"], tx_dut_ports[ports_info["dut_iface"]],
            setup["neighbor_sniff_ports"])


def test_src_ip_is_class_e(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, ports_info):
    """
    @summary: Verify that packet with source IP address in class E is dropped and L3 drop counter incremented
    """
    ip_list = ["240.0.0.1", "255.255.255.254"]

    for ip_class_e in ip_list:
        log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"], pkt_fields["ipv4_dst"],
                        ip_class_e)

        pkt = testutils.simple_tcp_packet(
            eth_dst=ports_info["dst_mac"], # DUT port
            eth_src=ports_info["src_mac"], # PTF port
            ip_src=ip_class_e,
            ip_dst=pkt_fields["ipv4_dst"], # VM source
            tcp_sport=pkt_fields["tcp_sport"],
            tcp_dport=pkt_fields["tcp_dport"])
        do_test("L3", pkt, ptfadapter, duthost, ports_info["ptf_tx_port_id"], tx_dut_ports[ports_info["dut_iface"]],
                setup["neighbor_sniff_ports"])


@pytest.mark.parametrize("addr_type, addr_direction", [("ipv4", "src"), ("ipv6", "src"), ("ipv4", "dst"),
                                                        ("ipv6", "dst")])
def test_ip_is_zero_addr(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, addr_type, addr_direction, ports_info):
    """
    @summary: Verify that packet with "0.0.0.0" source or destination IP address is dropped and L3 drop counter incremented
    """
    zero_ipv4 = "0.0.0.0"
    zero_ipv6 = "::0"

    pkt_params = {
        "eth_dst": ports_info["dst_mac"], # DUT port
        "eth_src": ports_info["src_mac"], # PTF port
        "tcp_sport": pkt_fields["tcp_sport"],
        "tcp_dport": pkt_fields["tcp_dport"]
        }

    if addr_type == "ipv4":
        if addr_direction == "src":
            pkt_params["ip_src"] = zero_ipv4
            pkt_params["ip_dst"] = pkt_fields["ipv4_dst"] # VM source
        elif addr_direction == "dst":
            pkt_params["ip_src"] = pkt_fields["ipv4_src"] # VM source
            pkt_params["ip_dst"] = zero_ipv4
        else:
            pytest.fail("Incorrect value specified for 'addr_direction'. Supported parameters: 'src' and 'dst'")
        pkt = testutils.simple_tcp_packet(**pkt_params)
    elif addr_type == "ipv6":
        if not pkt_fields["ipv6_dst"]:
            pytest.skip("BGP neighbour with IPv6 addr was not found")
        if addr_direction == "src":
            pkt_params["ipv6_src"] = zero_ipv6
            pkt_params["ipv6_dst"] = pkt_fields["ipv6_dst"] # VM source
        elif addr_direction == "dst":
            pkt_params["ipv6_src"] = pkt_fields["ipv6_src"] # VM source
            pkt_params["ipv6_dst"] = zero_ipv6
        else:
            pytest.fail("Incorrect value specified for 'addr_direction'. Supported parameters: 'src' and 'dst'")
        pkt = testutils.simple_tcpv6_packet(**pkt_params)
    else:
        pytest.fail("Incorrect value specified for 'addr_type' test parameter. Supported parameters: 'ipv4' or 'ipv6'")

    logger.info(pkt_params)
    do_test("L3", pkt, ptfadapter, duthost, ports_info["ptf_tx_port_id"], tx_dut_ports[ports_info["dut_iface"]],
            setup["dut_to_ptf_port_map"].values())


@pytest.mark.parametrize("addr_direction", ["src", "dst"])
def test_ip_link_local(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, addr_direction, ports_info):
    """
    @summary: Verify that packet with link-local address "169.254.0.0/16" is dropped and L3 drop counter incremented
    """
    link_local_ip = "169.254.10.125"

    pkt_params = {
        "eth_dst": ports_info["dst_mac"], # DUT port
        "eth_src": ports_info["src_mac"], # PTF port
        "tcp_sport": pkt_fields["tcp_sport"],
        "tcp_dport": pkt_fields["tcp_dport"]
        }

    if addr_direction == "src":
        pkt_params["ip_src"] = link_local_ip
        pkt_params["ip_dst"] = pkt_fields["ipv4_dst"] # VM source
    elif addr_direction == "dst":
        pkt_params["ip_src"] = pkt_fields["ipv4_src"] # VM source
        pkt_params["ip_dst"] = link_local_ip
    else:
        pytest.fail("Incorrect value specified for 'addr_direction'. Supported parameters: 'src' and 'dst'")
    pkt = testutils.simple_tcp_packet(**pkt_params)

    logger.info(pkt_params)
    do_test("L3", pkt, ptfadapter, duthost, ports_info["ptf_tx_port_id"], tx_dut_ports[ports_info["dut_iface"]],
            setup["neighbor_sniff_ports"])


def test_loopback_filter(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, ports_info):
    """
    @summary: Verify that packet drops by loopback-filter. Loop-back filter means that route to the host
              with DST IP of received packet exists on received interface
    """
    ip_dst = None
    vm_name = setup["mg_facts"]["minigraph_neighbors"][ports_info["dut_iface"]]["name"]

    for item in setup["mg_facts"]["minigraph_bgp"]:
        if item["name"] == vm_name:
            ip_dst = item["addr"]
            break
    if ip_dst is None:
        pytest.skip("Testcase is not supported on current interface")

    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"], ip_dst, pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"], # DUT port
        eth_src=ports_info["src_mac"], # PTF port
        ip_src=pkt_fields["ipv4_src"], # PTF source
        ip_dst=ip_dst,
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"])

    do_test("L3", pkt, ptfadapter, duthost, ports_info["ptf_tx_port_id"], tx_dut_ports[ports_info["dut_iface"]],
            setup["neighbor_sniff_ports"])


def test_ip_pkt_with_exceeded_mtu(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, mtu_config, ports_info):
    """
    @summary: Verify that IP packet with exceeded MTU is dropped and L3 drop counter incremented
    """
    if  "vlan" in tx_dut_ports[ports_info["dut_iface"]].lower():
        pytest.skip("Test case is not supported on VLAN interface")

    tmp_port_mtu = 1500

    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"], pkt_fields["ipv4_dst"],
                    pkt_fields["ipv4_src"])
    # Set temporal MTU. This will be restored by 'mtu' fixture
    mtu_config.set_mtu(tmp_port_mtu, tx_dut_ports[ports_info["dut_iface"]])

    pkt = testutils.simple_tcp_packet(
        pktlen=9100,
        eth_dst=ports_info["dst_mac"], # DUT port
        eth_src=ports_info["src_mac"], # PTF port
        ip_src=pkt_fields["ipv4_src"], # PTF source
        ip_dst=pkt_fields["ipv4_dst"], # VM IP address
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
        )

    do_test("L2", pkt, ptfadapter, duthost, ports_info["ptf_tx_port_id"], ports_info["dut_iface"], setup["neighbor_sniff_ports"],
            l2_col_key=RX_ERR)


def test_ip_pkt_with_expired_ttl(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, ports_info):
    """
    @summary: Verify that IP packet with TTL=0 is dropped and L3 drop counter incremented
    """
    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"], pkt_fields["ipv4_dst"],
                    pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"], # DUT port
        eth_src=ports_info["src_mac"], # PTF port
        ip_src=pkt_fields["ipv4_src"], # PTF source
        ip_dst=pkt_fields["ipv4_dst"], # VM IP address
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"],
        ip_ttl=0)

    do_test("L3", pkt, ptfadapter, duthost, ports_info["ptf_tx_port_id"], tx_dut_ports[ports_info["dut_iface"]],
            setup["neighbor_sniff_ports"])


@pytest.mark.parametrize("igmp_version,msg_type", [("v1", "general_query"), ("v3", "general_query"), ("v1", "membership_report"),
("v2", "membership_report"), ("v3", "membership_report"), ("v2", "leave_group")])
def test_non_routable_igmp_pkts(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, igmp_version, msg_type, ports_info):
    """
    @summary: Verify IGMP non-routable packets dropped by DUT and L3 drop counter incremented
    """
    # IGMP Types:
    # 0x11 = Membership Query
    # 0x12 = Version 1 Membership Report
    # 0x16 = Version 2 Membership Report
    # 0x17 = Leave Group

    # IP destination address according to the RFC 2236:
    # Message Type                  Destination Group
    # ------------                  -----------------
    # General Query                 ALL-SYSTEMS (224.0.0.1)
    # Group-Specific Query          The group being queried
    # Membership Report             The group being reported
    # Leave Message                 ALL-ROUTERS (224.0.0.2)

    # TODO: fix this workaround as of now current PTF and Scapy versions do not support creation of IGMP packets
    # Temporaly created hex of IGMP packet layer by using scapy version 2.4.3.
    # Example how to get HEX of specific IGMP packets:
    # v3_membership_query = IGMPv3(type=0x11, mrcode=0, chksum=None)/scapy.contrib.igmpv3.IGMPv3mq(gaddr="224.0.0.1",
    # srcaddrs=["172.16.11.1", "10.0.0.59"], qrv=1, qqic=125, numsrc=2)
    # gr_obj = scapy.contrib.igmpv3.IGMPv3gr(rtype=1, auxdlen=0, maddr="224.2.2.4", numsrc=2, srcaddrs=["172.16.11.1",
    # "10.0.0.59"]).build()
    # v3_membership_report = IGMPv3(type=0x22, mrcode=0, chksum=None)/scapy.contrib.igmpv3.IGMPv3mr(res2=0x00, numgrp=1,
    # records=[gr_obj]).build()
    # The rest packets are build like "simple_igmp_packet" function from PTF testutils.py

    from scapy.contrib.igmp import IGMP
    Ether = testutils.scapy.Ether
    IP = testutils.scapy.IP

    if  "vlan" in tx_dut_ports[ports_info["dut_iface"]].lower() and msg_type == "membership_report":
        pytest.skip("Test case is not supported on VLAN interface")

    igmp_proto = 0x02
    multicast_group_addr = "224.1.1.1"
    ethernet_dst = "01:00:5e:01:01:01"
    ip_dst = {"general_query": "224.0.0.1",
              "membership_report": multicast_group_addr}
    igmp_types = {"v1": {"general_query": IGMP(type=0x11, gaddr="224.0.0.1"),
                         "membership_report": IGMP(type=0x12, gaddr=multicast_group_addr)},
                  "v2": {"membership_report": IGMP(type=0x16, gaddr=multicast_group_addr),
                         "leave_group": IGMP(type=0x17, gaddr=multicast_group_addr)},
                  "v3": {"general_query": "\x11\x00L2\xe0\x00\x00\x01\x01}\x00\x02\xac\x10\x0b\x01\n\x00\x00;",
                         "membership_report": "\"\x009\xa9\x00\x00\x00\x01\x01\x00\x00\x02\xe0\x02\x02\x04\xac\x10\x0b\x01\n\x00\x00;"}
    }

    if igmp_version == "v3":
        pkt = testutils.simple_ip_packet(
            eth_dst=ethernet_dst,
            eth_src=ports_info["src_mac"],
            ip_src=pkt_fields["ipv4_src"],
            ip_dst=ip_dst[msg_type],
            ip_ttl=1,
            ip_proto=igmp_proto
        )
        del pkt["Raw"]
        pkt = pkt / igmp_types[igmp_version][msg_type]
    else:
        eth_layer = Ether(src=ports_info["src_mac"], dst=ethernet_dst)
        ip_layer = IP(src=pkt_fields["ipv4_src"], )
        igmp_layer = igmp_types[igmp_version][msg_type]
        assert igmp_layer.igmpize(ip=ip_layer, ether=eth_layer), "Can't create IGMP packet"
        pkt = eth_layer/ip_layer/igmp_layer

    log_pkt_params(ports_info["dut_iface"], ethernet_dst, ports_info["src_mac"], pkt.getlayer("IP").dst, pkt_fields["ipv4_src"])
    do_test("L3", pkt, ptfadapter, duthost, ports_info["ptf_tx_port_id"], tx_dut_ports[ports_info["dut_iface"]],
            setup["dut_to_ptf_port_map"].values())


def test_absent_ip_header(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, ports_info):
    """
    @summary: Verify that packets with absent IP header are dropped and L3 drop counter incremented
    """
    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"], pkt_fields["ipv4_dst"],
                    pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"], # DUT port
        eth_src=ports_info["src_mac"], # PTF port
        ip_src=pkt_fields["ipv4_src"], # PTF source
        ip_dst=pkt_fields["ipv4_dst"],
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
        )
    tcp = pkt[testutils.scapy.scapy.all.TCP]
    del pkt[testutils.scapy.scapy.all.IP]
    pkt.type = 0x800
    pkt = pkt/tcp

    do_test("L3", pkt, ptfadapter, duthost, ports_info["ptf_tx_port_id"], tx_dut_ports[ports_info["dut_iface"]],
            setup["neighbor_sniff_ports"])


@pytest.mark.parametrize("pkt_field, value", [("version", 1), ("chksum", 10), ("ihl", 1)])
def test_broken_ip_header(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, pkt_field, value, ports_info):
    """
    @summary: Verify that packets with broken IP header are dropped and L3 drop counter incremented
    """
    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"], pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"], # DUT port
        eth_src=ports_info["src_mac"], # PTF port
        ip_src=pkt_fields["ipv4_src"], # PTF source
        ip_dst=pkt_fields["ipv4_dst"],
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
        )
    setattr(pkt[testutils.scapy.scapy.all.IP], pkt_field, value)
    do_test("L3", pkt, ptfadapter, duthost, ports_info["ptf_tx_port_id"], tx_dut_ports[ports_info["dut_iface"]],
            setup["neighbor_sniff_ports"])


@pytest.mark.parametrize("eth_dst", ["01:00:5e:00:01:02", "ff:ff:ff:ff:ff:ff"])
def test_unicast_ip_incorrect_eth_dst(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, eth_dst, ports_info):
    """
    @summary: Verify that packets with multicast/broadcast ethernet dst are dropped on L3 interfaces and L3 drop counter incremented
    """
    if  "vlan" in tx_dut_ports[ports_info["dut_iface"]].lower():
        pytest.skip("Test case is not supported on VLAN interface")

    log_pkt_params(ports_info["dut_iface"], eth_dst, ports_info["src_mac"], pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=eth_dst, # DUT port
        eth_src=ports_info["src_mac"], # PTF port
        ip_src=pkt_fields["ipv4_src"], # PTF source
        ip_dst=pkt_fields["ipv4_dst"],
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
        )
    do_test("L3", pkt, ptfadapter, duthost, ports_info["ptf_tx_port_id"], tx_dut_ports[ports_info["dut_iface"]],
            setup["neighbor_sniff_ports"])


def test_acl_drop(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, acl_setup, ports_info):
    """
    @summary: Verify that DUT drops packet with SRC IP 20.0.0.0/24 matched by ingress ACL and ACL drop counter incremented
    """
    if tx_dut_ports[ports_info["dut_iface"]] not in duthost.acl_facts()["ansible_facts"]["ansible_acl_facts"]["DATAACL"]["ports"]:
        pytest.skip("RX DUT port absent in 'DATAACL' table")

    ip_src = "20.0.0.5"

    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"], pkt_fields["ipv4_dst"], ip_src)

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"], # DUT port
        eth_src=ports_info["src_mac"], # PTF port
        ip_src=ip_src,
        ip_dst=pkt_fields["ipv4_dst"],
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
        )
    base_verification("ACL", pkt, ptfadapter, duthost, ports_info["ptf_tx_port_id"], tx_dut_ports[ports_info["dut_iface"]])

    # Verify packets were not egresed the DUT
    exp_pkt = expected_packet_mask(pkt)
    exp_pkt.set_do_not_care_scapy(packet.IP, 'ip_src')
    testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=setup["neighbor_sniff_ports"])


def test_egress_drop_on_down_link(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, rif_port_down, ports_info):
    """
    @summary: Verify that packets on ingress port are dropped when egress RIF link is down and check that L3 drop counter incremented
    """
    ip_dst = rif_port_down
    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"], ip_dst, pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"], # DUT port
        eth_src=ports_info["src_mac"], # PTF port
        ip_src=pkt_fields["ipv4_src"], # PTF source
        ip_dst=ip_dst,
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
        )
    do_test("L3", pkt, ptfadapter, duthost, ports_info["ptf_tx_port_id"], tx_dut_ports[ports_info["dut_iface"]],
            setup["neighbor_sniff_ports"])
