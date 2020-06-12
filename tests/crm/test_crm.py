import pytest
import time
import re
import json

from jinja2 import Template
from common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from common.helpers.assertions import pytest_assert
from common.helpers.generators import generate_ips
from collections import OrderedDict


logger = logging.getLogger(__name__)

CRM_POLLING_INTERVAL = 1
CRM_UPDATE_TIME = 4

THR_VERIFY_CMDS = OrderedDict([
    ("exceeded_used", "bash -c \"crm config thresholds {{crm_cli_res}}  type used; crm config thresholds {{crm_cli_res}} low {{crm_used|int - 1}}; crm config thresholds {{crm_cli_res}} high {{crm_used|int}}\""),
    ("clear_used", "bash -c \"crm config thresholds {{crm_cli_res}} type used && crm config thresholds {{crm_cli_res}} low {{crm_used|int}} && crm config thresholds {{crm_cli_res}} high {{crm_used|int + 1}}\""),
    ("exceeded_free", "bash -c \"crm config thresholds {{crm_cli_res}} type free && crm config thresholds {{crm_cli_res}} low {{crm_avail|int - 1}} && crm config thresholds {{crm_cli_res}} high {{crm_avail|int}}\""),
    ("clear_free", "bash -c \"crm config thresholds {{crm_cli_res}} type free && crm config thresholds {{crm_cli_res}} low {{crm_avail|int}} && crm config thresholds {{crm_cli_res}} high {{crm_avail|int + 1}}\""),
    ("exceeded_percentage", "bash -c \"crm config thresholds {{crm_cli_res}} type percentage && crm config thresholds {{crm_cli_res}} low {{th_lo|int}} && crm config thresholds {{crm_cli_res}} high {{th_hi|int}}\""),
    ("clear_percentage", "bash -c \"crm config thresholds {{crm_cli_res}} type percentage && crm config thresholds {{crm_cli_res}} low {{th_lo|int}} && crm config thresholds {{crm_cli_res}} high {{th_hi|int}}\"")
])

EXPECT_EXCEEDED = ".* THRESHOLD_EXCEEDED .*"
EXPECT_CLEAR = ".* THRESHOLD_CLEAR .*"

RESTORE_CMDS = {"test_crm_route": [],
                "test_crm_nexthop": [],
                "test_crm_neighbor": [],
                "test_crm_nexthop_group": [],
                "test_acl_entry": [],
                "test_acl_counter": [],
                "test_crm_fdb_entry": [],
                "test_crm_vnet_bitmap": [],
                "crm_cli_res": None}


@pytest.fixture(scope="module", autouse=True)
def crm_interface(duthost, testbed):
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)["ansible_facts"]
    if testbed["topo"]["name"] == "t1":
        crm_intf1 = mg_facts["minigraph_interfaces"][0]["attachto"]
        crm_intf2 = mg_facts["minigraph_interfaces"][2]["attachto"]
    elif testbed["topo"]["name"] in ["t0", "t1-lag", "t0-52", "t0-56", "t0-64", "t0-116"]:
        crm_intf1 = mg_facts["minigraph_portchannel_interfaces"][0]["attachto"]
        crm_intf2 = mg_facts["minigraph_portchannel_interfaces"][2]["attachto"]
    else:
        pytest.skip("Unsupported topology for current test cases - {}".format(testbed["topo"]["name"]))
    yield (crm_intf1, crm_intf2)


@pytest.fixture(scope="module", autouse=True)
def set_polling_interval(duthost):
    wait_time = 2
    duthost.command("crm config polling interval {}".format(CRM_POLLING_INTERVAL))["stdout"]
    logger.info("Waiting {} sec for CRM counters to become updated".format(wait_time))
    time.sleep(wait_time)


@pytest.fixture(scope="module")
def collector(duthost):
    """ Fixture for sharing variables beatween test cases """
    data = {}
    yield data


def apply_acl_config(duthost, test_name, collector):
    """ Create acl rule defined in config file. Return ACL table key. """
    base_dir = os.path.dirname(os.path.realpath(__file__))
    template_dir = os.path.join(base_dir, "templates")
    acl_rules_template = "acl.json"
    dut_tmp_dir = "/tmp"

    duthost.command("mkdir -p {}".format(dut_tmp_dir))
    dut_conf_file_path = os.path.join(dut_tmp_dir, acl_rules_template)

    # Define test cleanup commands
    RESTORE_CMDS[test_name].append("rm -rf {}".format(dut_conf_file_path))
    RESTORE_CMDS[test_name].append("acl-loader delete")

    logger.info("Generating config for ACL rule, ACL table - DATAACL")
    duthost.template(src=os.path.join(template_dir, acl_rules_template), dest=dut_conf_file_path)

    logger.info("Applying {}".format(dut_conf_file_path))
    duthost.command("acl-loader update full {}".format(dut_conf_file_path))

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    collector["acl_tbl_key"] = get_acl_tbl_key(duthost)


def get_acl_tbl_key(duthost):
    # Get ACL entry keys
    cmd = "redis-cli --raw -n 1 KEYS *SAI_OBJECT_TYPE_ACL_ENTRY*"
    acl_tbl_keys = duthost.command(cmd)["stdout"].split()

    # Get ethertype for ACL entry and match ACL which was configured to ethertype value
    cmd = "redis-cli -n 1 HGET {item} SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE"
    for item in acl_tbl_keys:
        out = duthost.command(cmd.format(item=item))["stdout"]
        if "2048" in out:
            key = item
            break
    else:
        pytest.fail("Ether type was not found in SAI ACL Entry table")

    # Get ACL table key
    cmd = "redis-cli -n 1 HGET {key} SAI_ACL_ENTRY_ATTR_TABLE_ID"
    oid = duthost.command(cmd.format(key=key))["stdout"]
    acl_tbl_key = "CRM:ACL_TABLE_STATS:{0}".format(oid.replace("oid:", ""))

    return acl_tbl_key


def get_used_percent(crm_used, crm_available):
    return crm_used * 100 / (crm_used + crm_available)


def verify_thresholds(duthost, **kwargs):
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix='crm_test')
    loganalyzer.load_common_config()
    for key, value in THR_VERIFY_CMDS.items():
        template = Template(value)
        if "exceeded" in key:
            loganalyzer.expect_regex = [EXPECT_EXCEEDED]
        elif "clear" in key:
            loganalyzer.expect_regex = [EXPECT_CLEAR]

        if "percentage" in key:
            used_percent = get_used_percent(kwargs["crm_used"], kwargs["crm_avail"])
            if used_percent < 1:
                logger.warning("CRM used entries is < 1 percent")
            if key == "exceeded_percentage":
                kwargs["th_lo"] = used_percent - 1
                kwargs["th_hi"] = used_percent
                loganalyzer.expect_regex = [EXPECT_EXCEEDED]
            elif key == "clear_percentage":
                kwargs["th_lo"] = used_percent
                kwargs["th_hi"] = used_percent + 1
                loganalyzer.expect_regex = [EXPECT_CLEAR]
        cmd = template.render(**kwargs)

        with loganalyzer:
            duthost.command(cmd)


def get_crm_stats(cmd, duthost):
    out = duthost.command(cmd)
    crm_stats_used = int(out["stdout_lines"][0])
    crm_stats_available = int(out["stdout_lines"][1])
    return crm_stats_used, crm_stats_available


@pytest.mark.parametrize("ip_ver,route_add_cmd,route_del_cmd", [("4", "ip route add 2.2.2.0/24 via {}",
                                                                "ip route del 2.2.2.0/24 via {}"),
                                                                ("6", "ip -6 route add 2001::/126 via {}",
                                                                "ip -6 route del 2001::/126 via {}")],
                                                                ids=["ipv4", "ipv6"])
def test_crm_route(duthost, crm_interface, ip_ver, route_add_cmd, route_del_cmd):
    RESTORE_CMDS["crm_cli_res"] = "ipv{ip_ver} route".format(ip_ver=ip_ver)

    # Get "crm_stats_ipv[4/6]_route" used and available counter value
    get_route_stats = "redis-cli --raw -n 2 HMGET CRM:STATS crm_stats_ipv{ip_ver}_route_used crm_stats_ipv{ip_ver}_route_available".format(ip_ver=ip_ver)
    crm_stats_route_used, crm_stats_route_available = get_crm_stats(get_route_stats, duthost)

    # Get NH IP
    cmd = "ip -{ip_ver} neigh show dev {crm_intf} nud reachable nud stale".format(ip_ver=ip_ver, crm_intf=crm_interface[0])
    out = duthost.command(cmd)
    pytest_assert(out["stdout"] != "", "Get Next Hop IP failed. Neighbor not found")
    nh_ip = [item.split()[0] for item in out["stdout"].split("\n") if "REACHABLE" in item][0]

    # Add IPv[4/6] route
    RESTORE_CMDS["test_crm_route"].append(route_del_cmd.format(nh_ip))
    duthost.command(route_add_cmd.format(nh_ip))

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_ipv[4/6]_route" used and available counter value
    new_crm_stats_route_used, new_crm_stats_route_available = get_crm_stats(get_route_stats, duthost)

    # Verify "crm_stats_ipv[4/6]_route_used" counter was incremented
    pytest_assert(new_crm_stats_route_used - crm_stats_route_used == 1, \
        "\"crm_stats_ipv{}_route_used\" counter was not incremented".format(ip_ver))
    # Verify "crm_stats_ipv[4/6]_route_available" counter was decremented
    pytest_assert(crm_stats_route_available - new_crm_stats_route_available >= 1, \
        "\"crm_stats_ipv{}_route_available\" counter was not decremented".format(ip_ver))

    # Remove IPv[4/6] route
    duthost.command(route_del_cmd.format(nh_ip))

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_ipv[4/6]_route" used and available counter value
    new_crm_stats_route_used, new_crm_stats_route_available = get_crm_stats(get_route_stats, duthost)

    # Verify "crm_stats_ipv[4/6]_route_used" counter was decremented
    pytest_assert(new_crm_stats_route_used - crm_stats_route_used == 0, \
        "\"crm_stats_ipv{}_route_used\" counter was not decremented".format(ip_ver))
    # Verify "crm_stats_ipv[4/6]_route_available" counter was incremented
    pytest_assert(new_crm_stats_route_available - crm_stats_route_available == 0, \
        "\"crm_stats_ipv{}_route_available\" counter was not incremented".format(ip_ver))

    # Verify thresholds for "IPv[4/6] route" CRM resource
    verify_thresholds(duthost, crm_cli_res=RESTORE_CMDS["crm_cli_res"],
        crm_used=new_crm_stats_route_used, crm_avail=new_crm_stats_route_available)


@pytest.mark.parametrize("ip_ver,nexthop", [("4", "2.2.2.2"), ("6", "2001::1")])
def test_crm_nexthop(duthost, crm_interface, ip_ver, nexthop):
    RESTORE_CMDS["crm_cli_res"] = "ipv{ip_ver} nexthop".format(ip_ver=ip_ver)
    nexthop_add_template = "ip neigh replace {nexthop} lladdr 11:22:33:44:55:66 dev {iface}"
    nexthop_del_template = "ip neigh del {nexthop} lladdr 11:22:33:44:55:66 dev {iface}"
    nexthop_add_cmd = nexthop_add_template.format(nexthop=nexthop, iface=crm_interface[0])
    nexthop_del_cmd = nexthop_del_template.format(nexthop=nexthop, iface=crm_interface[0])
    del_neigh_template = """for s in {{neigh_ip_list}}
    do
        ip neigh del ${s} lladdr 11:22:33:44:55:66 dev {{iface}}
        echo deleted - ${s}
    done"""
    del_neighbours_template = Template(del_neigh_template)

    # Get "crm_stats_ipv[4/6]_nexthop" used and available counter value
    get_nexthop_stats = "redis-cli --raw -n 2 HMGET CRM:STATS crm_stats_ipv{ip_ver}_nexthop_used crm_stats_ipv{ip_ver}_nexthop_available".format(ip_ver=ip_ver)
    crm_stats_nexthop_used, crm_stats_nexthop_available = get_crm_stats(get_nexthop_stats, duthost)

    # Add nexthop
    RESTORE_CMDS["test_crm_nexthop"].append(nexthop_del_cmd)
    duthost.command(nexthop_add_cmd)

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_ipv[4/6]_nexthop" used and available counter value
    new_crm_stats_nexthop_used, new_crm_stats_nexthop_available = get_crm_stats(get_nexthop_stats, duthost)

    # Verify "crm_stats_ipv[4/6]_nexthop_used" counter was incremented
    pytest_assert(new_crm_stats_nexthop_used - crm_stats_nexthop_used >= 1, \
        "\"crm_stats_ipv{}_nexthop_used\" counter was not incremented".format(ip_ver))
    # Verify "crm_stats_ipv[4/6]_nexthop_available" counter was decremented
    pytest_assert(crm_stats_nexthop_available - new_crm_stats_nexthop_available >= 1, \
        "\"crm_stats_ipv{}_nexthop_available\" counter was not decremented".format(ip_ver))

    # Remove nexthop
    duthost.command(nexthop_del_cmd)

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_ipv[4/6]_nexthop" used and available counter value
    new_crm_stats_nexthop_used, new_crm_stats_nexthop_available = get_crm_stats(get_nexthop_stats, duthost)

    # Verify "crm_stats_ipv[4/6]_nexthop_used" counter was decremented
    pytest_assert(new_crm_stats_nexthop_used - crm_stats_nexthop_used == 0, \
        "\"crm_stats_ipv{}_nexthop_used\" counter was not decremented".format(ip_ver))
    # Verify "crm_stats_ipv[4/6]_nexthop_available" counter was incremented
    pytest_assert(new_crm_stats_nexthop_available - crm_stats_nexthop_available == 0, \
        "\"crm_stats_ipv{}_nexthop_available\" counter was not incremented".format(ip_ver))

    # Add new neighbor entries to correctly calculate used CRM resources in percentage
    used_percent = get_used_percent(new_crm_stats_nexthop_used, new_crm_stats_nexthop_available)
    if used_percent < 1:
        neighbours_num = (new_crm_stats_nexthop_used + new_crm_stats_nexthop_available) / 100
        lst = []
        if ip_ver == "4":
            ip_addr_list = [item.split("/")[0] for item in generate_ips(neighbours_num, "2.2.0.0/16", lst)]
            # Store CLI command to delete all created neighbours
            RESTORE_CMDS["test_crm_nexthop"].append(del_neighbours_template.render(neigh_ip_list=" ".join(ip_addr_list),
                iface=crm_interface[0]))
            for item in ip_addr_list:
                cmd = nexthop_add_template.format(nexthop=item, iface=crm_interface[0])
                duthost.command(cmd)
    # Verify thresholds for "IPv[4/6] nexthop" CRM resource
    verify_thresholds(duthost, crm_cli_res=RESTORE_CMDS["crm_cli_res"], crm_used=new_crm_stats_nexthop_used, crm_avail=new_crm_stats_nexthop_available)


@pytest.mark.parametrize("ip_ver,neighbor", [("4", "2.2.2.2"), ("6", "2001::1")])
def test_crm_neighbor(duthost, crm_interface, ip_ver, neighbor):
    RESTORE_CMDS["crm_cli_res"] = "ipv{ip_ver} neighbor".format(ip_ver=ip_ver)
    neighbor_add_cmd = "ip neigh replace {neighbor} lladdr 11:22:33:44:55:66 dev {iface}".format(neighbor=neighbor, iface=crm_interface[0])
    neighbor_del_cmd = "ip neigh del {neighbor} lladdr 11:22:33:44:55:66 dev {iface}".format(neighbor=neighbor, iface=crm_interface[0])

    # Get "crm_stats_ipv[4/6]_neighbor" used and available counter value
    get_neighbor_stats = "redis-cli --raw -n 2 HMGET CRM:STATS crm_stats_ipv{ip_ver}_neighbor_used crm_stats_ipv{ip_ver}_neighbor_available".format(ip_ver=ip_ver)
    crm_stats_neighbor_used, crm_stats_neighbor_available = get_crm_stats(get_neighbor_stats, duthost)

    # Add neighbor
    RESTORE_CMDS["test_crm_neighbor"].append(neighbor_del_cmd)
    duthost.command(neighbor_add_cmd)

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_ipv[4/6]_neighbor" used and available counter value
    new_crm_stats_neighbor_used, new_crm_stats_neighbor_available = get_crm_stats(get_neighbor_stats, duthost)

    # Verify "crm_stats_ipv4_neighbor_used" counter was incremented
    pytest_assert(new_crm_stats_neighbor_used - crm_stats_neighbor_used >= 1, \
        "\"crm_stats_ipv4_neighbor_used\" counter was not incremented")
    # Verify "crm_stats_ipv4_neighbor_available" counter was decremented
    pytest_assert(crm_stats_neighbor_available - new_crm_stats_neighbor_available >= 1, \
        "\"crm_stats_ipv4_neighbor_available\" counter was not decremented")

    # Remove neighbor
    duthost.command(neighbor_del_cmd)

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_ipv[4/6]_neighbor" used and available counter value
    new_crm_stats_neighbor_used, new_crm_stats_neighbor_available = get_crm_stats(get_neighbor_stats, duthost)

    # Verify "crm_stats_ipv4_neighbor_used" counter was decremented
    pytest_assert(new_crm_stats_neighbor_used - crm_stats_neighbor_used >= 0, \
        "\"crm_stats_ipv4_neighbor_used\" counter was not decremented")
    # Verify "crm_stats_ipv4_neighbor_available" counter was incremented
    pytest_assert(new_crm_stats_neighbor_available - crm_stats_neighbor_available == 0, \
        "\"crm_stats_ipv4_neighbor_available\" counter was not incremented")

    # Verify thresholds for "IPv[4/6] neighbor" CRM resource
    verify_thresholds(duthost, crm_cli_res=RESTORE_CMDS["crm_cli_res"], crm_used=new_crm_stats_neighbor_used,
        crm_avail=new_crm_stats_neighbor_available)


@pytest.mark.parametrize("group_member,network,ip_ver", [(False, "2.2.2.0/24", "4"), (False, "2001::/126", "6"), (True, "2.2.2.0/24", "4"), (True, "2001::/126", "6")])
def test_crm_nexthop_group(duthost, crm_interface, group_member, network, ip_ver):
    RESTORE_CMDS["crm_cli_res"] = "nexthop group member" if group_member else "nexthop group object"
    get_group_stats = "redis-cli --raw -n 2 HMGET CRM:STATS crm_stats_nexthop_group_used crm_stats_nexthop_group_available"
    get_group_member_stats = "redis-cli --raw -n 2 HMGET CRM:STATS crm_stats_nexthop_group_member_used crm_stats_nexthop_group_member_available"
    nexthop_add_cmd = "ip -{ip_ver} route add {network} nexthop via {nh_ip1} nexthop via {nh_ip2}"
    nexthop_del_cmd = "ip -{ip_ver} route del {network} nexthop via {nh_ip1} nexthop via {nh_ip2}"

    # Get "crm_stats_nexthop_group_[member]" used and available counter value
    get_nexthop_group_stats = get_group_member_stats if group_member else get_group_stats
    nexthop_group_used, nexthop_group_available = get_crm_stats(get_nexthop_group_stats, duthost)

    # Get NH IP 1
    cmd = "ip -{ip_ver} neigh show dev {crm_intf} nud reachable nud stale".format(ip_ver=ip_ver, crm_intf=crm_interface[0])
    out = duthost.command(cmd)
    pytest_assert(out["stdout"] != "", "Get Next Hop IP failed. Neighbor not found")
    nh_ip1 = [item.split()[0] for item in out["stdout"].split("\n") if "REACHABLE" in item][0]

    # Get NH IP 2
    cmd = "ip -{ip_ver} neigh show dev {crm_intf} nud reachable nud stale".format(ip_ver=ip_ver, crm_intf=crm_interface[1])
    out = duthost.command(cmd)
    pytest_assert(out["stdout"] != "", "Get Next Hop IP failed. Neighbor not found")
    nh_ip2 = [item.split()[0] for item in out["stdout"].split("\n") if "REACHABLE" in item][0]

    nexthop_add_cmd = nexthop_add_cmd.format(ip_ver=ip_ver, network=network, nh_ip1=nh_ip1, nh_ip2=nh_ip2)
    nexthop_del_cmd = nexthop_del_cmd.format(ip_ver=ip_ver, network=network, nh_ip1=nh_ip1, nh_ip2=nh_ip2)

    # Add nexthop group members
    RESTORE_CMDS["test_crm_nexthop_group"].append(nexthop_del_cmd)
    duthost.command(nexthop_add_cmd)

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_nexthop_group_[member]" used and available counter value
    new_nexthop_group_used, new_nexthop_group_available = get_crm_stats(get_nexthop_group_stats, duthost)

    # Verify "crm_stats_nexthop_group_[member]_used" counter was incremented
    pytest_assert(new_nexthop_group_used - nexthop_group_used == 2, \
        "\"crm_stats_nexthop_group_{}used\" counter was not incremented".format("member_" if group_member else ""))

    # Verify "crm_stats_nexthop_group_[member]_available" counter was decremented
    pytest_assert(nexthop_group_available - new_nexthop_group_available >= 2, \
        "\"crm_stats_nexthop_group_{}available\" counter was not decremented".format("member_" if group_member else ""))

    # Remove nexthop group members
    duthost.command(nexthop_del_cmd)

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_nexthop_group_[member]" used and available counter value
    new_nexthop_group_used, new_nexthop_group_available = get_crm_stats(get_nexthop_group_stats, duthost)

    # Verify "crm_stats_nexthop_group_[member]_used" counter was decremented
    pytest_assert(new_nexthop_group_used - nexthop_group_used == 0, \
        "\"crm_stats_nexthop_group_{}used\" counter was not decremented".format("member_" if group_member else ""))

    # Verify "crm_stats_nexthop_group_[member]_available" counter was incremented
    pytest_assert(new_nexthop_group_available - nexthop_group_available == 0, \
        "\"crm_stats_nexthop_group_{}available\" counter was not incremented".format("member_" if group_member else ""))

    verify_thresholds(duthost, crm_cli_res=RESTORE_CMDS["crm_cli_res"], crm_used=new_nexthop_group_used,
        crm_avail=new_nexthop_group_available)


def test_acl_entry(duthost, collector):
    apply_acl_config(duthost, "test_acl_entry", collector)
    acl_tbl_key = collector["acl_tbl_key"]

    RESTORE_CMDS["crm_cli_res"] = "acl group entry"

    crm_stats_acl_entry_used = 0
    crm_stats_acl_entry_available = 0

    # Get new "crm_stats_acl_entry" used and available counter value
    cmd = "redis-cli --raw -n 2 HMGET {acl_tbl_key} crm_stats_acl_entry_used crm_stats_acl_entry_available"
    std_out = duthost.command(cmd.format(acl_tbl_key=acl_tbl_key))["stdout_lines"]
    new_crm_stats_acl_entry_used = int(std_out[0])
    new_crm_stats_acl_entry_available = int(std_out[1])

    # Verify "crm_stats_acl_entry_used" counter was incremented
    pytest_assert(new_crm_stats_acl_entry_used - crm_stats_acl_entry_used == 2, \
        "\"crm_stats_acl_entry_used\" counter was not incremented")

    crm_stats_acl_entry_available = new_crm_stats_acl_entry_available + new_crm_stats_acl_entry_used

    # Verify thresholds for "ACL entry" CRM resource
    verify_thresholds(duthost, crm_cli_res=RESTORE_CMDS["crm_cli_res"], crm_used=new_crm_stats_acl_entry_used,
        crm_avail=new_crm_stats_acl_entry_available)

    # Remove ACL
    duthost.command("acl-loader delete")

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_acl_entry" used and available counter value
    cmd = "redis-cli --raw -n 2 HMGET {acl_tbl_key} crm_stats_acl_entry_used crm_stats_acl_entry_available"
    std_out = duthost.command(cmd.format(acl_tbl_key=acl_tbl_key))["stdout_lines"]
    new_crm_stats_acl_entry_used = int(std_out[0])
    new_crm_stats_acl_entry_available = int(std_out[1])

    # Verify "crm_stats_acl_entry_used" counter was decremented
    pytest_assert(new_crm_stats_acl_entry_used - crm_stats_acl_entry_used == 0, \
        "\"crm_stats_acl_entry_used\" counter was not decremented")

    # Verify "crm_stats_acl_entry_available" counter was incremented
    pytest_assert(new_crm_stats_acl_entry_available - crm_stats_acl_entry_available == 0, \
        "\"crm_stats_acl_entry_available\" counter was not incremented")


def test_acl_counter(duthost, collector):
    if not "acl_tbl_key" in collector:
        pytest.skip("acl_tbl_key is not retreived")
    acl_tbl_key = collector["acl_tbl_key"]

    RESTORE_CMDS["crm_cli_res"] = "acl group counter"

    crm_stats_acl_counter_used = 0
    crm_stats_acl_counter_available = 0

    # Get original "crm_stats_acl_counter_available" counter value
    cmd = "redis-cli -n 2 HGET {acl_tbl_key} crm_stats_acl_counter_available"
    std_out = int(duthost.command(cmd.format(acl_tbl_key=acl_tbl_key))["stdout"])
    original_crm_stats_acl_counter_available = std_out

    apply_acl_config(duthost, "test_acl_counter", collector)

    # Get new "crm_stats_acl_counter" used and available counter value
    cmd = "redis-cli --raw -n 2 HMGET {acl_tbl_key} crm_stats_acl_counter_used crm_stats_acl_counter_available"
    std_out = duthost.command(cmd.format(acl_tbl_key=acl_tbl_key))["stdout_lines"]
    new_crm_stats_acl_counter_used = int(std_out[0])
    new_crm_stats_acl_counter_available = int(std_out[1])

    # Verify "crm_stats_acl_counter_used" counter was incremented
    pytest_assert(new_crm_stats_acl_counter_used - crm_stats_acl_counter_used == 2, \
        "\"crm_stats_acl_counter_used\" counter was not incremented")

    crm_stats_acl_counter_available = new_crm_stats_acl_counter_available + new_crm_stats_acl_counter_used

    # Verify thresholds for "ACL entry" CRM resource
    verify_thresholds(duthost, crm_cli_res=RESTORE_CMDS["crm_cli_res"], crm_used=new_crm_stats_acl_counter_used,
        crm_avail=new_crm_stats_acl_counter_available)

    # Remove ACL
    duthost.command("acl-loader delete")

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_acl_counter" used and available counter value
    cmd = "redis-cli --raw -n 2 HMGET {acl_tbl_key} crm_stats_acl_counter_used crm_stats_acl_counter_available"
    std_out = duthost.command(cmd.format(acl_tbl_key=acl_tbl_key))["stdout_lines"]
    new_crm_stats_acl_counter_used = int(std_out[0])
    new_crm_stats_acl_counter_available = int(std_out[1])

    # Verify "crm_stats_acl_counter_used" counter was decremented
    pytest_assert(new_crm_stats_acl_counter_used - crm_stats_acl_counter_used == 0, \
        "\"crm_stats_acl_counter_used\" counter was not decremented")

    # Verify "crm_stats_acl_counter_available" counter was incremented
    pytest_assert(new_crm_stats_acl_counter_available - crm_stats_acl_counter_available >= 0, \
        "\"crm_stats_acl_counter_available\" counter was not incremented")

    # Verify "crm_stats_acl_counter_available" counter was equal to original value
    pytest_assert(original_crm_stats_acl_counter_available - new_crm_stats_acl_counter_available == 0, \
        "\"crm_stats_acl_counter_available\" counter is not equal to original value")


def test_crm_fdb_entry(duthost):
    RESTORE_CMDS["crm_cli_res"] = "fdb"

    # Configure test restore commands
    # Remove VLAN member required for FDB entry
    RESTORE_CMDS["test_crm_fdb_entry"].append("config vlan member del 2 Ethernet0")
    # Remove VLAN required for FDB entry
    RESTORE_CMDS["test_crm_fdb_entry"].append("config vlan del 2")
    # Remove FDB entry
    RESTORE_CMDS["test_crm_fdb_entry"].append("fdbclear")
    # Remove FDB JSON config from switch.
    RESTORE_CMDS["test_crm_fdb_entry"].append("rm /tmp/fdb.json")
    # Remove FDB JSON config from SWSS container
    RESTORE_CMDS["test_crm_fdb_entry"].append("docker exec -i swss rm /fdb.json")
    # Restart arp_update
    RESTORE_CMDS["test_crm_fdb_entry"].append("docker exec -i swss supervisorctl start arp_update")

    # Stop arp_update
    cmd = "docker exec -i swss supervisorctl stop arp_update"
    duthost.command(cmd)

    # Remove FDB entry
    cmd = "fdbclear"
    duthost.command(cmd)

    # Get "crm_stats_fdb_entry" used and available counter value
    cmd = "redis-cli --raw -n 2 HMGET CRM:STATS crm_stats_fdb_entry_used crm_stats_fdb_entry_available"
    crm_stats_fdb_entry_used, crm_stats_fdb_entry_available = get_crm_stats(cmd, duthost)

    # Copy FDB JSON config to switch.
    base_dir = os.path.dirname(os.path.realpath(__file__))
    template_dir = os.path.join(base_dir, "../../ansible/roles/test/tasks/crm/fdb.json")
    duthost.template(src=template_dir, dest="/tmp")

    # Copy FDB JSON config to SWSS container
    cmd = "docker cp /tmp/fdb.json swss:/"
    duthost.command(cmd)

    # Add FDB entry
    cmd = "docker exec -i swss swssconfig /fdb.json"
    duthost.command(cmd)

    # Add VLAN required for FDB entry
    cmd = "config vlan add 2"
    duthost.command(cmd)

    # Add VLAN member required for FDB entry
    cmd = "config vlan member add 2 Ethernet0"
    duthost.command(cmd)

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_fdb_entry" used and available counter value
    cmd = "redis-cli --raw -n 2 HMGET CRM:STATS crm_stats_fdb_entry_used crm_stats_fdb_entry_available"
    new_crm_stats_fdb_entry_used, new_crm_stats_fdb_entry_available = get_crm_stats(cmd, duthost)

    # Verify "crm_stats_fdb_entry_used" counter was incremented
    pytest_assert(new_crm_stats_fdb_entry_used - crm_stats_fdb_entry_used == 1, \
        "Counter 'crm_stats_fdb_entry_used' was not incremented")

    # Verify "crm_stats_fdb_entry_available" counter was decremented
    pytest_assert(crm_stats_fdb_entry_available - new_crm_stats_fdb_entry_available == 1, \
        "Counter 'crm_stats_fdb_entry_available' was not incremented")

    # Verify thresholds for "FDB entry" CRM resource
    verify_thresholds(duthost, crm_cli_res=RESTORE_CMDS["crm_cli_res"], crm_used=new_crm_stats_fdb_entry_used,
        crm_avail=new_crm_stats_fdb_entry_available)

    # Remove FDB entry
    cmd = "fdbclear"
    duthost.command(cmd)

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_fdb_entry" used and available counter value
    cmd = "redis-cli --raw -n 2 HMGET CRM:STATS crm_stats_fdb_entry_used crm_stats_fdb_entry_available"
    new_crm_stats_fdb_entry_used, new_crm_stats_fdb_entry_available = get_crm_stats(cmd, duthost)

    # Verify "crm_stats_fdb_entry_used" counter was decremented
    pytest_assert(new_crm_stats_fdb_entry_used == 0, "Counter 'crm_stats_fdb_entry_used' was not decremented")

    # Verify "crm_stats_fdb_entry_available" counter was incremented
    pytest_assert(new_crm_stats_fdb_entry_available - crm_stats_fdb_entry_available >= 0, \
        "Counter 'crm_stats_fdb_entry_available' was not incremented")


def test_crm_vnet_bitmap(duthost, testbed):
    if duthost.facts["asic_type"] != "mellanox":
        pytest.skip("Unsupported ASIC type")

    cmd_copy_route_config = "docker cp /tmp/vnet.del.route.json swss:/vnet.route.json"
    cmd_apply_route_config = "docker exec swss sh -c \"swssconfig /vnet.route.json\""
    cmd_del_interf_addr = "docker exec -i database redis-cli -n 4 del \"VLAN_INTERFACE|{ifname}|{ifip}\""
    cmd_del_interf = "docker exec -i database redis-cli -n 4 del \"VLAN_INTERFACE|{ifname}\""
    cmd_del_vnet = "docker exec -i database redis-cli -n 4 del \"VNET|{vnet}\""

    template_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "templates")
    vnet_conf = os.path.join(template_dir, "vnet.conf.json")
    vnet_intf = os.path.join(template_dir, "vnet.intf.json")
    vnet_route_add = os.path.join(template_dir, "vnet.add.route.json")
    vnet_route_del = os.path.join(template_dir, "vnet.del.route.json")
    vlan_ifname = None
    vlan_ifip = None
    vnet_name = None

    with open(vnet_conf) as conf_file:
        conf_json = json.load(conf_file)

        for key, value in conf_json["VLAN_INTERFACE"].items():
            if "|" in key:
                vlan_ifname, vlan_ifip = key.split("|")
            else:
                vnet_name = value["vnet_name"]

    # Configure test restore commands
    RESTORE_CMDS["test_crm_vnet_bitmap"].append(cmd_copy_route_config)
    RESTORE_CMDS["test_crm_vnet_bitmap"].append(cmd_apply_route_config)
    RESTORE_CMDS["test_crm_vnet_bitmap"].append(cmd_del_interf_addr.format(ifname=vlan_ifname, ifip=vlan_ifip))
    RESTORE_CMDS["test_crm_vnet_bitmap"].append(cmd_del_interf.format(ifname=vlan_ifname))
    RESTORE_CMDS["test_crm_vnet_bitmap"].append(cmd_del_vnet.format(vnet=vnet_name))

    # Copy configs to switch
    duthost.template(src=vnet_conf, dest="/tmp")
    duthost.template(src=vnet_intf, dest="/tmp")
    duthost.template(src=vnet_route_add, dest="/tmp")
    duthost.template(src=vnet_route_del, dest="/tmp")
    time.sleep(1)

    # Clear FDB table
    cmd = "sonic-clear fdb all"
    duthost.command(cmd)

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get "crm_stats_ipv4_route" used and available counter value
    cmd = "redis-cli --raw -n 2 HMGET CRM:STATS crm_stats_ipv4_route_used crm_stats_ipv4_route_available"
    crm_stats_ipv4_route_used, crm_stats_ipv4_route_available = get_crm_stats(cmd, duthost)

    # Get "crm_stats_ipv4_nexthop" used and available counter value
    cmd = "redis-cli --raw -n 2 HMGET CRM:STATS crm_stats_ipv4_nexthop_used crm_stats_ipv4_nexthop_available"
    crm_stats_ipv4_nexthop_used, crm_stats_ipv4_nexthop_available = get_crm_stats(cmd, duthost)

    # Get "crm_stats_ipv4_neighbor" used and available counter value
    cmd = "redis-cli --raw -n 2 HMGET CRM:STATS crm_stats_ipv4_neighbor_used crm_stats_ipv4_neighbor_available"
    crm_stats_ipv4_neighbor_used, crm_stats_ipv4_neighbor_available = get_crm_stats(cmd, duthost)

    # Get "crm_stats_fdb_entry" used and available counter value
    cmd = "redis-cli --raw -n 2 HMGET CRM:STATS crm_stats_fdb_entry_used crm_stats_fdb_entry_available"
    crm_stats_fdb_entry_used, crm_stats_fdb_entry_available = get_crm_stats(cmd, duthost)

    # Apply VNet Vxlan configuration
    duthost.command("config load -y /tmp/vnet.conf.json")
    time.sleep(3)
    # Copy route configuration to swss container
    duthost.command("docker cp /tmp/vnet.add.route.json swss:/vnet.route.json")
    # Apply route json configuration
    duthost.command("docker exec swss sh -c \"swssconfig /vnet.route.json\"")
    time.sleep(3)


    # Get number of VNET interfaces
    num = int(duthost.shell("grep \"Vlan\" /tmp/vnet.intf.json | wc -l")["stdout_lines"][0])
    # Only regular routes are counted here since there is no CRM counter for BITMAP VNET routes.
    # There is one such route per each interface so it is equal to number of VNET interfaces.
    ipv4_route_num = num

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_ipv4_route" used and available counter value
    cmd = "redis-cli --raw -n 2 HMGET CRM:STATS crm_stats_ipv4_route_used crm_stats_ipv4_route_available"
    new_crm_stats_ipv4_route_used, new_crm_stats_ipv4_route_available = get_crm_stats(cmd, duthost)

    # Get new "crm_stats_ipv4_nexthop" used and available counter value
    cmd = "redis-cli --raw -n 2 HMGET CRM:STATS crm_stats_ipv4_nexthop_used crm_stats_ipv4_nexthop_available"
    new_crm_stats_ipv4_nexthop_used, new_crm_stats_ipv4_nexthop_available = get_crm_stats(cmd, duthost)

    # Verify "crm_stats_ipv4_route_used" counter was incremented
    pytest_assert(new_crm_stats_ipv4_route_used - crm_stats_ipv4_route_used == ipv4_route_num, \
        "'crm_stats_ipv4_route_used' counter was not incremented")

    # Verify "crm_stats_ipv4_route_available" counter was decremented
    pytest_assert(crm_stats_ipv4_route_available - new_crm_stats_ipv4_route_available >= ipv4_route_num, \
        "\"crm_stats_ipv4_route_available\" counter was not decremented")

    # Verify "crm_stats_ipv4_nexthop_used" counter was incremented
    pytest_assert(new_crm_stats_ipv4_nexthop_used - crm_stats_ipv4_nexthop_used == 1, \
        "\"crm_stats_ipv4_nexthop_used\" counter was not incremented")

    # Verify "crm_stats_ipv4_nexthop_available" counter was decremented
    pytest_assert(crm_stats_ipv4_nexthop_available - new_crm_stats_ipv4_nexthop_available >= 1, \
        "\"crm_stats_ipv4_nexthop_available\" counter was not decremented")

    # Clean VNET config
    # Copy route configuration to swss container
    duthost.command(cmd_copy_route_config)
    time.sleep(1)
    # Apply route json configuration
    duthost.command(cmd_apply_route_config)
    time.sleep(3)

    # Remove VNET interfaces addresses
    duthost.command(cmd_del_interf_addr.format(ifname=vlan_ifname, ifip=vlan_ifip))

    # Remove VNET interfaces
    duthost.command(cmd_del_interf.format(ifname=vlan_ifname))

    # Remove VNETs
    duthost.command(cmd_del_vnet.format(vnet=vnet_name))

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_ipv4_route" used and available counter value
    cmd = "redis-cli --raw -n 2 HMGET CRM:STATS crm_stats_ipv4_route_used crm_stats_ipv4_route_available"
    new_crm_stats_ipv4_route_used, new_crm_stats_ipv4_route_available = get_crm_stats(cmd, duthost)

    # Get new "crm_stats_ipv4_nexthop" used and available counter value
    cmd = "redis-cli --raw -n 2 HMGET CRM:STATS crm_stats_ipv4_nexthop_used crm_stats_ipv4_nexthop_available"
    new_crm_stats_ipv4_nexthop_used, new_crm_stats_ipv4_nexthop_available = get_crm_stats(cmd, duthost)

    # Verify "crm_stats_ipv4_route_used" counter was decremented
    pytest_assert(new_crm_stats_ipv4_route_used - crm_stats_ipv4_route_used == 0, \
        "\"crm_stats_ipv4_route_used\" counter was not decremented")

    # Verify "crm_stats_ipv4_route_available" counter was incremented
    pytest_assert(new_crm_stats_ipv4_route_available - crm_stats_ipv4_route_available == 0, \
        "\"crm_stats_ipv4_route_available\" counter was not incremented")

    # Verify "crm_stats_ipv4_nexthop_used" counter was decremented
    pytest_assert(new_crm_stats_ipv4_nexthop_used - crm_stats_ipv4_nexthop_used == 0, \
        "\"crm_stats_ipv4_nexthop_used\" counter was not decremented")

    # Verify "crm_stats_ipv4_nexthop_available" counter was incremented
    pytest_assert(new_crm_stats_ipv4_nexthop_available - crm_stats_ipv4_nexthop_available == 0, \
        "\"crm_stats_ipv4_nexthop_available\" counter was not incremented")
