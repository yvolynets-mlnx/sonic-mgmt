"""
Verify that the hw-management service is running properly

This script covers test case 'Ensure that the hw-management service is running properly' in the SONiC platform test
plan: https://github.com/Azure/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""

from ansible_host import AnsibleHost
from check_hw_mgmt_service import check_hw_management_service


def test_hw_management_service_status(localhost, ansible_adhoc, testbed):
    """This test case is to verify that the hw-management service is running properly
    """
    hostname = testbed['dut']
    ans_host = AnsibleHost(ansible_adhoc, hostname)

    check_hw_management_service(ans_host)
