"""
This module describes possibility of loganalyzer usage.
It is just for example, it does not test anything.
"""

import pytest
import time
import os
import sys

from ansible_host import ansible_host
sys.path.append(os.path.join(os.path.split(__file__)[0], "pytest_loganalyzer"))
from pytest_loganalyzer.pytest_loganalyzer import PytestLogAnalyzer
from pytest_loganalyzer.pytest_loganalyzer import COMMON_MATCH


def adder(x, y=10, z=0):
    return x + y

def test_loganalyzer_functionality(localhost, ansible_adhoc, testbed):
    """
    @summary: Example of loganalyzer usage
    """
    hostname = testbed['dut']
    ans_host = ansible_host(ansible_adhoc, hostname)

    log = PytestLogAnalyzer(ansible_host=ans_host, marker_prefix="test_loganalyzer")
    # Read existed common regular expressions located with legacy loganalyzer module
    log.load_common_config()
    # Add start marker to the DUT syslog
    log.init()
    # Emulate that new error messages appears in the syslog
    time.sleep(1)
    ans_host.command("echo '---------- ERR: text 1 error --------------' >> /var/log/syslog")
    ans_host.command("echo '---------- THRESHOLD_CLEAR test1 xyz test2 --------------' >> /var/log/syslog")
    time.sleep(2)
    ans_host.command("echo '---------- kernel: says Oops --------------' >> /var/log/syslog")

    # Perform syslog analysis based on added messages
    result = log.analyze()
    if not result:
        pytest.fail("Log analyzer failed.")
    assert result["total"]["match"] == 2, "Found errors: {}".format(result)
    # Download extracted syslog file from DUT to the local host
    res_save_log = log.save_extracted_log(dest=os.getcwd() + "/../log/syslog")

    # Example: update previously configured marker
    # Now start marker will have new prefix
    log.update_marker_prefix("log")

    # Execute function and analyze logs during function execution
    # Return tuple of (FUNCTION_RESULT, LOGANALYZER_RESULT)
    run_cmd_result = log.run_cmd(adder, 5, y=5, z=11)

    # Clear current regexp match list
    log.match_regex = []
    # Load regular expressions from the specified file
    reg_exp = log.parse_regexp_file(src=COMMON_MATCH)
    # Extend existed match regular expresiions with previously read
    log.match_regex.extend(reg_exp)

    # Verify that new regular expressions are found by log analyzer
    log.init()
    ans_host.command("echo '---------- kernel: says Oops --------------' >> /var/log/syslog")
    result = log.analyze()
    if not result:
        pytest.fail("Log analyzer failed.")
    assert result["total"]["match"] == 1, "Found errors: {}".format(result)
