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

ADD_RM_CMDS = {"test_crm_ipv4_route": {"add": "ip route add 2.2.2.0/24 via {}",
                                       "rm": "ip route del 2.2.2.0/24 via {}"},
                "test_crm_ipv6_route": {}}
# TODO: continue fill in -> test_crm_ipv6_route
# TODO: add messages to each assert


@pytest.fixture(scope="module", autouse=True)
def crm_interface(duthost, testbed):
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)["ansible_facts"]
    if testbed["topo"]["name"] == "t1":
        # TODO:
        pass
    elif testbed["topo"]["name"] in ["t0", "t1-lag", "t0-52", "t0-56", "t0-64", "t0-116"]:
        crm_intf1 = mg_facts["minigraph_portchannel_interfaces"][0]["attachto"]
        crm_intf2 = mg_facts["minigraph_portchannel_interfaces"][2]["attachto"]
    else:
        pytest.skip("Unsupported topology for current test cases - {}".format(testbed["topo"]["name"]))
    yield (crm_intf1, crm_intf2)

@pytest.fixture(scope="module", autouse=True)
def set_polling_interval(duthost):
    duthost.command("crm config polling interval {}".format(CRM_POLLING_INTERVAL))["stdout"]
    # TODO: add logging message
    # Check timeout
    time.sleep(2)

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

        # loganalyzer.expect_regex = [LOG_EXPECT_POLICY_FILE_INVALID] # TODO: add for 10 times verification
        with loganalyzer:
            duthost.command(cmd)

def test_crm_ipv4_route(duthost, crm_interface, crm_cli_res="ipv4 route"):
    # Get "crm_stats_ipv4_route" used and available counter value
    cmd = "redis-cli --raw -n 2 HMGET CRM:STATS crm_stats_ipv4_route_used crm_stats_ipv4_route_available"
    out = duthost.command(cmd)
    crm_stats_ipv4_route_used = int(out["stdout_lines"][0])
    crm_stats_ipv4_route_available = int(out["stdout_lines"][1])

    # Get NH IP
    cmd = "ip -4 neigh show dev {crm_intf} nud reachable nud stale".format(crm_intf=crm_interface[0])
    out = duthost.command(cmd)
    assert out != "", "Get Next Hop IP failed. Neighbour not found"

    nh_ip= out["stdout"].split()[0]

    # Add IPv4 route
    cmd = ADD_RM_CMDS["test_crm_ipv4_route"]["add"].format(nh_ip)
    duthost.command(cmd)

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_ipv4_route" used and available counter value
    cmd = "redis-cli --raw -n 2 HMGET CRM:STATS crm_stats_ipv4_route_used crm_stats_ipv4_route_available"
    out = duthost.command(cmd)
    new_crm_stats_ipv4_route_used = int(out["stdout_lines"][0])
    new_crm_stats_ipv4_route_available = int(out["stdout_lines"][1])

    # Verify "crm_stats_ipv4_route_used" counter was incremented
    assert new_crm_stats_ipv4_route_used - crm_stats_ipv4_route_used == 1

    # Verify "crm_stats_ipv4_route_available" counter was decremented
    assert crm_stats_ipv4_route_available - new_crm_stats_ipv4_route_available >= 1

    # Remove IPv4 route
    ADD_RM_CMDS["test_crm_ipv4_route"]["rm"] = ADD_RM_CMDS["test_crm_ipv4_route"]["rm"].format(nh_ip)
    cmd = ADD_RM_CMDS["test_crm_ipv4_route"]["rm"]
    duthost.command(cmd)

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_ipv4_route" used and available counter value
    cmd = "redis-cli --raw -n 2 HMGET CRM:STATS crm_stats_ipv4_route_used crm_stats_ipv4_route_available"
    out = duthost.command(cmd)
    new_crm_stats_ipv4_route_used = int(out["stdout_lines"][0])
    new_crm_stats_ipv4_route_available = int(out["stdout_lines"][1])

    # Verify "crm_stats_ipv4_route_used" counter was decremented
    assert new_crm_stats_ipv4_route_used - crm_stats_ipv4_route_used == 0

    # Verify "crm_stats_ipv4_route_available" counter was incremented
    assert new_crm_stats_ipv4_route_available - crm_stats_ipv4_route_available == 0
    # Verify thresholds for "IPv4 route" CRM resource
    verify_thresholds(duthost, crm_cli_res=crm_cli_res, crm_used=new_crm_stats_ipv4_route_used, crm_avail=new_crm_stats_ipv4_route_available)


def test_crm_ipv6_route(duthost, crm_interface, crm_cli_res="ipv6 route"):
    # Get "crm_stats_ipv6_route" used and available counter value
    cmd = "redis-cli --raw -n 2 HMGET CRM:STATS crm_stats_ipv6_route_used crm_stats_ipv6_route_available"
    out = duthost.command(cmd)
    crm_stats_ipv6_route_used = int(out["stdout_lines"][0])
    crm_stats_ipv6_route_available = int(out["stdout_lines"][1])

    # Get NH IP
    cmd = "ip -6 neigh show dev {} nud reachable nud stale".format(crm_interface[0])
    out = duthost.command(cmd)

    pattern = re.compile(r"(?:[0-9a-fA-F]:?){12}")
    assert len(re.findall(pattern, out["stdout"])) == 1, "Get Next Hop IP failed. Neighbour not found"

    nh_ip = out["stdout"].split()[0]

    # Add IPv6 route
    cmd = "ip -6 route add 2001::/126 via {}".format(nh_ip)
    duthost.command(cmd)

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_ipv6_route" used and available counter value
    cmd = "redis-cli --raw -n 2 HMGET CRM:STATS crm_stats_ipv6_route_used crm_stats_ipv6_route_available"
    out = duthost.command(cmd)
    new_crm_stats_ipv6_route_used = int(out["stdout_lines"][0])
    new_crm_stats_ipv6_route_available = int(out["stdout_lines"][1])

    # Verify "crm_stats_ipv6_route_used" counter was incremented
    assert new_crm_stats_ipv6_route_used - crm_stats_ipv6_route_used >= 1

    # Verify "crm_stats_ipv6_route_available" counter was decremented
    assert crm_stats_ipv6_route_available - new_crm_stats_ipv6_route_available >= 1

    # Remove IPv6 route
    cmd = "ip -6 route del 2001::/126 via {}".format(nh_ip)
    duthost.command(cmd)

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_ipv6_route" used and available counter value
    cmd = "redis-cli --raw -n 2 HMGET CRM:STATS crm_stats_ipv6_route_used crm_stats_ipv6_route_available"
    out = duthost.command(cmd)
    new_crm_stats_ipv6_route_used = int(out["stdout_lines"][0])
    new_crm_stats_ipv6_route_available = int(out["stdout_lines"][1])

    # Verify "crm_stats_ipv6_route_used" counter was decremented
    assert new_crm_stats_ipv6_route_used - crm_stats_ipv6_route_used == 0

    # Verify "crm_stats_ipv6_route_available" counter was incremented
    assert new_crm_stats_ipv6_route_available - crm_stats_ipv6_route_available == 0

    # Verify thresholds for "IPv6 route" CRM resource
    verify_thresholds(duthost, crm_cli_res=crm_cli_res, crm_used=new_crm_stats_ipv6_route_used, crm_avail=new_crm_stats_ipv6_route_available)
