import pytest
import time
import re

from jinja2 import Template
from common.plugins.loganalyzer.loganalyzer import LogAnalyzer


logger = logging.getLogger(__name__)

CRM_POLLING_INTERVAL = 1
CRM_UPDATE_TIME = 4
THR_VERIFY_CMDS = {
    "exceeded_used": "bash -c \"crm config thresholds {{crm_cli_res}}  type used; crm config thresholds {{crm_cli_res}} low {{crm_used|int - 1}}; crm config thresholds {{crm_cli_res}} high {{crm_used|int}}\"",
    "clear_used": "bash -c \"crm config thresholds {{crm_cli_res}} type used && crm config thresholds {{crm_cli_res}} low {{crm_used|int}} && crm config thresholds {{crm_cli_res}} high {{crm_used|int + 1}}\"",
    "exceeded_free": "bash -c \"crm config thresholds {{crm_cli_res}} type free && crm config thresholds {{crm_cli_res}} low {{crm_avail|int - 1}} && crm config thresholds {{crm_cli_res}} high {{crm_avail|int}}\"",
    "clear_free": "bash -c \"crm config thresholds {{crm_cli_res}} type free && crm config thresholds {{crm_cli_res}} low {{crm_avail|int}} && crm config thresholds {{crm_cli_res}} high {{crm_avail|int + 1}}\"",
    "exceeded_percentage": "bash -c \"crm config thresholds {{crm_cli_res}} type percentage && crm config thresholds {{crm_cli_res}} low {{th_lo|int}} && crm config thresholds {{crm_cli_res}} high {{th_hi|int}}\"",
    "clear_percentage": "bash -c \"crm config thresholds {{crm_cli_res}} type percentage && crm config thresholds {{crm_cli_res}} low {{th_lo|int}} && crm config thresholds {{crm_cli_res}} high {{th_hi|int}}\""
    }

RESTORE_CMDS = {"test_crm_route": [],
                "test_crm_nexthop": [],
                "test_crm_neighbor": [],
                "test_crm_nexthop_group": [],
                "crm_cli_res": None}
# TODO: add messages to each assert
# TODO: create ansible wrapper for this tests


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

def verify_thresholds(duthost, **kwargs):
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix='crm_test')
    for key, value in THR_VERIFY_CMDS.items():
        template = Template(value)
        if key == "exceeded_percentage":
            kwargs["th_lo"] = (kwargs["crm_used"] * 100 / (kwargs["crm_used"] + kwargs["crm_avail"])) - 1
            kwargs["th_hi"] = kwargs["crm_used"] * 100 / (kwargs["crm_used"] + kwargs["crm_avail"])
        elif key == "clear_percentage":
            kwargs["th_lo"] = kwargs["crm_used"] * 100 / (kwargs["crm_used"] + kwargs["crm_avail"])
            kwargs["th_hi"] = (kwargs["crm_used"] * 100 / (kwargs["crm_used"] + kwargs["crm_avail"])) + 1
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
    assert out != "", "Get Next Hop IP failed. Neighbor not found"
    nh_ip = [item.split()[0] for item in out["stdout"].split("\n") if "REACHABLE" in item][0]

    # Add IPv[4/6] route
    RESTORE_CMDS["test_crm_route"].append(route_del_cmd.format(nh_ip))
    duthost.command(route_add_cmd.format(nh_ip))

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_ipv[4/6]_route" used and available counter value
    new_crm_stats_route_used, new_crm_stats_route_available = get_crm_stats(get_route_stats, duthost)

    # Verify "crm_stats_ipv[4/6]_route_used" counter was incremented
    assert new_crm_stats_route_used - crm_stats_route_used == 1
    # Verify "crm_stats_ipv[4/6]_route_available" counter was decremented
    assert crm_stats_route_available - new_crm_stats_route_available >= 1

    # Remove IPv[4/6] route
    duthost.command(route_del_cmd.format(nh_ip))

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_ipv[4/6]_route" used and available counter value
    new_crm_stats_route_used, new_crm_stats_route_available = get_crm_stats(get_route_stats, duthost)

    # Verify "crm_stats_ipv[4/6]_route_used" counter was decremented
    assert new_crm_stats_route_used - crm_stats_route_used == 0
    # Verify "crm_stats_ipv[4/6]_route_available" counter was incremented
    assert new_crm_stats_route_available - crm_stats_route_available == 0

    # Verify thresholds for "IPv[4/6] route" CRM resource
    verify_thresholds(duthost, crm_cli_res=RESTORE_CMDS["crm_cli_res"],
        crm_used=new_crm_stats_route_used, crm_avail=new_crm_stats_route_available)


@pytest.mark.parametrize("ip_ver,nexthop", [("4", "2.2.2.2"), ("6", "2001::1")])
def test_crm_nexthop(duthost, crm_interface, ip_ver, nexthop):
    RESTORE_CMDS["crm_cli_res"] = "ipv{ip_ver} nexthop".format(ip_ver=ip_ver)
    nexthop_add_cmd = "ip neigh replace {nexthop} lladdr 11:22:33:44:55:66 dev {iface}".format(nexthop=nexthop, iface=crm_interface[0])
    nexthop_del_cmd = "ip neigh del {nexthop} lladdr 11:22:33:44:55:66 dev {iface}".format(nexthop=nexthop, iface=crm_interface[0])

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
    assert new_crm_stats_nexthop_used - crm_stats_nexthop_used >= 1
    # Verify "crm_stats_ipv[4/6]_nexthop_available" counter was decremented
    assert crm_stats_nexthop_available - new_crm_stats_nexthop_available >= 1

    # Remove nexthop
    duthost.command(nexthop_del_cmd)

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_ipv[4/6]_nexthop" used and available counter value
    new_crm_stats_nexthop_used, new_crm_stats_nexthop_available = get_crm_stats(get_nexthop_stats, duthost)

    # Verify "crm_stats_ipv[4/6]_nexthop_used" counter was decremented
    assert new_crm_stats_nexthop_used - crm_stats_nexthop_used == 0
    # Verify "crm_stats_ipv[4/6]_nexthop_available" counter was incremented
    assert new_crm_stats_nexthop_available - crm_stats_nexthop_available == 0

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
    assert new_crm_stats_neighbor_used - crm_stats_neighbor_used >= 1
    # Verify "crm_stats_ipv4_neighbor_available" counter was decremented
    assert crm_stats_neighbor_available - new_crm_stats_neighbor_available >= 1

    # Remove neighbor
    duthost.command(neighbor_del_cmd)

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_ipv[4/6]_neighbor" used and available counter value
    new_crm_stats_neighbor_used, new_crm_stats_neighbor_available = get_crm_stats(get_neighbor_stats, duthost)

    # Verify "crm_stats_ipv4_neighbor_used" counter was decremented
    assert new_crm_stats_neighbor_used - crm_stats_neighbor_used >= 0
    # Verify "crm_stats_ipv4_neighbor_available" counter was incremented
    assert new_crm_stats_neighbor_available - crm_stats_neighbor_available == 0

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

    # Get "crm_stats_nexthop_group[member]" used and available counter value
    get_nexthop_group_stats = get_group_member_stats if group_member else get_group_stats
    nexthop_group_used, nexthop_group_available = get_crm_stats(get_nexthop_group_stats, duthost)

    # Get NH IP 1
    cmd = "ip -{ip_ver} neigh show dev {crm_intf} nud reachable nud stale".format(ip_ver=ip_ver, crm_intf=crm_interface[0])
    out = duthost.command(cmd)
    assert out != "", "Get Next Hop IP failed. Neighbor not found"
    nh_ip1 = [item.split()[0] for item in out["stdout"].split("\n") if "REACHABLE" in item][0]

    # Get NH IP 2
    cmd = "ip -{ip_ver} neigh show dev {crm_intf} nud reachable nud stale".format(ip_ver=ip_ver, crm_intf=crm_interface[1])
    out = duthost.command(cmd)
    assert out != "", "Get Next Hop IP failed. Neighbor not found"
    nh_ip2 = [item.split()[0] for item in out["stdout"].split("\n") if "REACHABLE" in item][0]

    nexthop_add_cmd = nexthop_add_cmd.format(ip_ver=ip_ver, network=network, nh_ip1=nh_ip1, nh_ip2=nh_ip2)
    nexthop_del_cmd = nexthop_del_cmd.format(ip_ver=ip_ver, network=network, nh_ip1=nh_ip1, nh_ip2=nh_ip2)

    # Add nexthop group members
    RESTORE_CMDS["test_crm_nexthop_group"].append(nexthop_del_cmd)
    duthost.command(nexthop_add_cmd)

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_nexthop_group_member" used and available counter value
    new_nexthop_group_used, new_nexthop_group_available = get_crm_stats(get_nexthop_group_stats, duthost)

    # Verify "crm_stats_nexthop_group_member_used" counter was incremented
    assert new_nexthop_group_used - nexthop_group_used == 2

    # Verify "crm_stats_nexthop_group_member_available" counter was decremented
    assert nexthop_group_available - new_nexthop_group_available >= 2

    # Remove nexthop group members
    duthost.command(nexthop_del_cmd)

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_nexthop_group_member" used and available counter value
    new_nexthop_group_used, new_nexthop_group_available = get_crm_stats(get_nexthop_group_stats, duthost)

    # Verify "crm_stats_nexthop_group_member_used" counter was decremented
    assert new_nexthop_group_used - nexthop_group_used == 0

    # Verify "crm_stats_nexthop_group_member_available" counter was incremented
    assert new_nexthop_group_available - nexthop_group_available == 0

    verify_thresholds(duthost, crm_cli_res=RESTORE_CMDS["crm_cli_res"], crm_used=new_nexthop_group_used,
        crm_avail=new_nexthop_group_available)
