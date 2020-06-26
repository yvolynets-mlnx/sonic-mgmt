import pytest
import time
import re
import json
import ipaddress

from jinja2 import Template
from common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from common.helpers.assertions import pytest_assert
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
    for key, value in THR_VERIFY_CMDS.items():
        template = Template(value)
        if "exceeded" in key:
            loganalyzer.expect_regex = [EXPECT_EXCEEDED]
        elif "clear" in key:
            loganalyzer.expect_regex = [EXPECT_CLEAR]

        if "percentage" in key:
            if "nexthop group" in kwargs["crm_cli_res"]:
                # TODO: Fix this. Temporal skip percentage verification for 'test_crm_nexthop_group' test case
                # Max supported ECMP group values is less then number of entries we need to configure
                # in order to test percentage threshold (Can't even reach 1 percent)
                # For test case used 'nexthop_group' need to be configured at least 1 percent from available
                continue
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


def generate_neighbors(amount, ip_ver):
    if ip_ver == "4":
        ip_addr_list = list(ipaddress.IPv4Network(u"%s" % "2.0.0.0/8").hosts())[0:amount]
        # ip_addr_list = " ".join([str(item) for item in ip_addr_list])
    elif ip_ver == "6":
        ip_addr_list = list(ipaddress.IPv6Network(u"%s" % "2001::/112").hosts())[0:amount]
        # ip_addr_list = " ".join([str(item) for item in ip_addr_list])
    else:
        pytest.fail("Incorrect IP version specified - {}".format(ip_ver))
    return ip_addr_list


def generate_routes(num, ip_type):
    if ip_type == "4":
        return " ".join([str(ipaddress.IPv4Address(u'2.0.0.1') + item) + "/32" for item in range(1, num + 1)])
    elif ip_type == "6":
        return " ".join([str(ipaddress.IPv6Address(u'2001::') + item) + "/128" for item in range(1, num + 1)])
    else:
        return None


def configure_nexthop_groups(amount, interface, ip_ver, duthost, test_name):
    # Template used to speedup execution many similar commands on DUT
    del_template = """
    ip -{{ip_ver}} route del 2.0.0.0/8 dev {{iface}}
    ip neigh del 2.0.0.1 lladdr 11:22:33:44:55:66 dev {{iface}}
    for s in {{neigh_ip_list}}
    do
        ip neigh del ${s} lladdr 11:22:33:44:55:66 dev {{iface}}
        ip -{{ip_ver}} route del ${s}/32 nexthop via ${s} nexthop via 2.0.0.1
    done"""
    add_template = """
    ip -{{ip_ver}} route add 2.0.0.0/8 dev {{iface}}
    ip neigh replace 2.0.0.1 lladdr 11:22:33:44:55:66 dev {{iface}}
    for s in {{neigh_ip_list}}
    do
        ip neigh replace ${s} lladdr 11:22:33:44:55:66 dev {{iface}}
        ip -{{ip_ver}} route add ${s}/32 nexthop via ${s} nexthop via 2.0.0.1
    done"""
    del_template = Template(del_template)
    add_template = Template(add_template)

    ip_addr_list = generate_neighbors(amount + 1, ip_ver)
    ip_addr_list = " ".join([str(item) for item in ip_addr_list[1:]])
    # Store CLI command to delete all created neighbors if test case will fail
    RESTORE_CMDS[test_name].append(del_template.render(ip_ver=ip_ver, iface=interface, neigh_ip_list=ip_addr_list))
    duthost.shell(add_template.render(ip_ver=ip_ver, iface=interface, neigh_ip_list=ip_addr_list))
    # Make sure CRM counters updated
    time.sleep(10)
    return del_template.render(ip_ver=ip_ver, iface=interface, neigh_ip_list=ip_addr_list)


def configure_neighbors(amount, interface, ip_ver, duthost, test_name):
    # Template used to speedup execution many similar commands on DUT
    del_template = """for s in {{neigh_ip_list}}
    do
        ip neigh del ${s} lladdr 11:22:33:44:55:66 dev {{iface}}
        echo deleted - ${s}
    done"""
    add_template = """for s in {{neigh_ip_list}}
    do
        ip neigh replace ${s} lladdr 11:22:33:44:55:66 dev {{iface}}
        echo added - ${s}
    done"""

    del_neighbors_template = Template(del_template)
    add_neighbors_template = Template(add_template)

    ip_addr_list = generate_neighbors(amount, ip_ver)
    ip_addr_list = " ".join([str(item) for item in ip_addr_list])

    # Store CLI command to delete all created neighbors if test case will fail
    RESTORE_CMDS[test_name].append(del_neighbors_template.render(neigh_ip_list=ip_addr_list,
        iface=interface))
    duthost.shell(add_neighbors_template.render(neigh_ip_list=ip_addr_list, iface=interface))
    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)
    return del_neighbors_template.render(neigh_ip_list=ip_addr_list, iface=interface)


@pytest.mark.parametrize("ip_ver,route_add_cmd,route_del_cmd", [("4", "ip route add 2.2.2.0/24 via {}",
                                                                "ip route del 2.2.2.0/24 via {}"),
                                                                ("6", "ip -6 route add 2001::/126 via {}",
                                                                "ip -6 route del 2001::/126 via {}")],
                                                                ids=["ipv4", "ipv6"])
def test_crm_route(duthost, crm_interface, ip_ver, route_add_cmd, route_del_cmd):
    RESTORE_CMDS["crm_cli_res"] = "ipv{ip_ver} route".format(ip_ver=ip_ver)

    # Template used to speedup execution of many similar commands on DUT
    del_template = """for s in {{routes_list}}
    do
        ip route del ${s} dev {{interface}}
        echo deleted route - ${s}
    done"""
    add_template = """for s in {{routes_list}}
    do
        ip route add ${s} dev {{interface}}
        echo added route - ${s}
    done"""

    del_routes_template = Template(del_template)
    add_routes_template = Template(add_template)

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

    used_percent = get_used_percent(new_crm_stats_route_used, new_crm_stats_route_available)
    if used_percent < 1:
        routes_num = (new_crm_stats_route_used + new_crm_stats_route_available) / 100
        if ip_ver == "4":
            routes_list = generate_routes(routes_num, "4")
        elif ip_ver == "6":
            routes_list = generate_routes(routes_num, "6")
        else:
            pytest.fail("Incorrect IP version specified - {}".format(ip_ver))
        # Store CLI command to delete all created neighbours if test case will fail
        RESTORE_CMDS["test_crm_nexthop"].append(del_routes_template.render(routes_list=routes_list, interface=crm_interface[0]))
        # Add test routes entries to correctly calculate used CRM resources in percentage
        duthost.shell(add_routes_template.render(routes_list=routes_list, interface=crm_interface[0]))
        # Make sure CRM counters updated
        time.sleep(CRM_UPDATE_TIME)

        # Get new "crm_stats_ipv[4/6]_route" used and available counter value
        new_crm_stats_route_used, new_crm_stats_route_available = get_crm_stats(get_route_stats, duthost)

    # Verify thresholds for "IPv[4/6] route" CRM resource
    verify_thresholds(duthost, crm_cli_res=RESTORE_CMDS["crm_cli_res"],
        crm_used=new_crm_stats_route_used, crm_avail=new_crm_stats_route_available)

    if used_percent < 1:
        # Remove test routes entries
        duthost.shell(del_routes_template.render(routes_list=routes_list, interface=crm_interface[0]))

@pytest.mark.parametrize("ip_ver,nexthop", [("4", "2.2.2.2"), ("6", "2001::1")])
def test_crm_nexthop(duthost, crm_interface, ip_ver, nexthop):
    RESTORE_CMDS["crm_cli_res"] = "ipv{ip_ver} nexthop".format(ip_ver=ip_ver)
    nexthop_add_cmd = "ip neigh replace {nexthop} lladdr 11:22:33:44:55:66 dev {iface}".format(nexthop=nexthop,
        iface=crm_interface[0])
    nexthop_del_cmd = "ip neigh del {nexthop} lladdr 11:22:33:44:55:66 dev {iface}".format(nexthop=nexthop,
        iface=crm_interface[0])

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

    used_percent = get_used_percent(new_crm_stats_nexthop_used, new_crm_stats_nexthop_available)
    if used_percent < 1:
        neighbours_num = (new_crm_stats_nexthop_used + new_crm_stats_nexthop_available) / 100
        # Add new neighbor entries to correctly calculate used CRM resources in percentage
        cleanup_cmd = configure_neighbors(amount=neighbours_num, interface=crm_interface[0], ip_ver=ip_ver, duthost=duthost,
            test_name="test_crm_nexthop")

        # Get new "crm_stats_ipv[4/6]_nexthop" used and available counter value
        new_crm_stats_nexthop_used, new_crm_stats_nexthop_available = get_crm_stats(get_nexthop_stats, duthost)

    # Verify thresholds for "IPv[4/6] nexthop" CRM resource
    verify_thresholds(duthost, crm_cli_res=RESTORE_CMDS["crm_cli_res"], crm_used=new_crm_stats_nexthop_used, crm_avail=new_crm_stats_nexthop_available)

    if used_percent < 1:
        # Remove test neighbour entries
        duthost.shell(cleanup_cmd)

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

    used_percent = get_used_percent(new_crm_stats_neighbor_used, new_crm_stats_neighbor_available)
    if used_percent < 1:
        neighbours_num = (new_crm_stats_neighbor_used + new_crm_stats_neighbor_available) / 100
        # Add new neighbor entries to correctly calculate used CRM resources in percentage
        cleanup_cmd = configure_neighbors(amount=neighbours_num, interface=crm_interface[0], ip_ver=ip_ver, duthost=duthost,
            test_name="test_crm_neighbor")

        # Get new "crm_stats_ipv[4/6]_neighbor" used and available counter value
        new_crm_stats_neighbor_used, new_crm_stats_neighbor_available = get_crm_stats(get_neighbor_stats, duthost)

    # Verify thresholds for "IPv[4/6] neighbor" CRM resource
    verify_thresholds(duthost, crm_cli_res=RESTORE_CMDS["crm_cli_res"], crm_used=new_crm_stats_neighbor_used,
        crm_avail=new_crm_stats_neighbor_available)

    if used_percent < 1:
        # Remove test neighbour entries
        duthost.shell(cleanup_cmd)


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
    pytest_assert(new_nexthop_group_used - nexthop_group_used == 1, \
        "\"crm_stats_nexthop_group_{}used\" counter was not incremented".format("member_" if group_member else ""))

    # Verify "crm_stats_nexthop_group_[member]_available" counter was decremented
    pytest_assert(nexthop_group_available - new_nexthop_group_available >= 1, \
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

    # Preconfiguration needed for used percentage verification
    # used_percent = get_used_percent(new_nexthop_group_used, new_nexthop_group_available)
    # if used_percent < 1:
    #     nexthop_group_num = (new_nexthop_group_used + new_nexthop_group_available) / 100
    #     # Increase default Linux configuration for ARP cache
    #     cmd = "sysctl -w net.ipv{}.neigh.default.gc_thresh{}={}"
    #     for thresh_id in range(1, 4):
    #         duthost.shell(cmd.format(ip_ver, thresh_id, nexthop_group_num + 100))

    #     # Add new neighbor entries to correctly calculate used CRM resources in percentage
    #     cleanup_cmd = configure_nexthop_groups(amount=nexthop_group_num, interface=crm_interface[0], ip_ver=ip_ver,
    #         duthost=duthost, test_name="test_crm_nexthop_group")
    #     # Get new "crm_stats_ipv[4/6]_neighbor" used and available counter value
    #     new_nexthop_group_used, new_nexthop_group_available = get_crm_stats(get_nexthop_group_stats, duthost)

    verify_thresholds(duthost, crm_cli_res=RESTORE_CMDS["crm_cli_res"], crm_used=new_nexthop_group_used,
        crm_avail=new_nexthop_group_available)

    # if used_percent < 1:
    #     # Remove test neighbour entries
    #     duthost.shell(cleanup_cmd)
    #     time.sleep(10)


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

# TODO: add CRM VNET Bitmap test case
