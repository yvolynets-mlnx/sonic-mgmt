"""
Test SAI key value for table size configuration.

This script is to cover the SAI key value for table size configuration feature.
"""
import json
import logging
import re
import time

import pytest

from common.utilities import wait, wait_until
from common.mellanox_data import SWITCH_MODELS as models
from common.errors import RunAnsibleModuleFail


@pytest.fixture(scope="module")
def common_setup_teardown(testbed_devices):
    """
    @summary: Fixture for setup and teardown for all the test cases in this script

    When table size is changed in sai.profile, a reboot is required for the new settings to take effect. To recover
    the testbed after testing, reboot is also required. It takes too much time to use reboot to recover SONiC DUT
    after each test case is executed. Purpose of this fixture is to reboot to recover testbed after all the test cases
    in this script have been executed.
    """
    logging.info("Start common setup, initialize instances for various devices")

    yield testbed_devices  # Test cases can call this function to pass in the (dut, localhost) objects for later cleanup

    logging.info("Start common teardown")

    dut = testbed_devices["dut"]
    dut_platform = dut.facts["platform"]
    dut_hwsku = dut.facts["hwsku"]
    localhost = testbed_devices["localhost"]

    reboot_required = False

    # Recover sai.profile settings
    sai_profile = "/usr/share/sonic/device/%s/%s/sai.profile" % (dut_platform, dut_hwsku)
    backup_sai_profile = sai_profile + ".backup"
    logging.info("sai.profile: %s" % sai_profile)
    if dut.stat(path=backup_sai_profile)["stat"]["exists"]:
        logging.info("Restore %s to %s" % (backup_sai_profile, sai_profile))
        dut.command("cp %s %s" % (backup_sai_profile, sai_profile))
        dut.file(path=backup_sai_profile, state="absent")
        reboot_required = True

    # For devices support warm-reboot, ensure that warm-reboot is recovered after testing
    hwsku_digits = re.findall(r"\d+", dut_hwsku)[0]
    sai_xml = "/usr/share/sonic/device/{}/{}/sai_{}.xml".format(dut_platform, dut_hwsku, hwsku_digits)
    if models[dut_hwsku]["reboot"]["warm_reboot"]:
        if dut.shell("grep '<issu-enabled>0</issu-enabled>' %s | wc -l" % sai_xml)["stdout"] == "1":
            line = "<issu-enabled>1</issu-enabled>"
            pattern = r"<issu-enabled>\d</issu-enabled>"
            dut.lineinfile(dest=sai_xml, regexp=pattern, line=line)
            reboot_required = True

    if reboot_required:
        logging.info("Reboot the DUT to restore")
        reboot_task, reboot_res = dut.command("reboot", module_async=True)
        logging.info("Wait for DUT to go down")
        try:
            localhost.wait_for(host=dut.hostname, port=22, state="stopped", delay=10, timeout=300)
        except RunAnsibleModuleFail as e:
            logging.error("DUT did not go down, exception: " + repr(e))
            if reboot_task.is_alive():
                logging.error("Rebooting is not completed")
                reboot_task.terminate()
            logging.error("reboot result %s" % str(reboot_res.get()))

        logging.info("Wait for DUT to come back")
        localhost.wait_for(host=dut.hostname, port=22, state="started", delay=10, timeout=300)

        logging.info("Wait until system is stable")
        wait_until(300, 30, dut.critical_services_fully_started)

    logging.info("Done common teardown")


def set_table_size(dut, table_size):
    """
    @summary: Set customized table size in sai.profile
    """
    sai_profile = "/usr/share/sonic/device/%s/%s/sai.profile" % (dut.facts["platform"], dut.facts["hwsku"])
    backup_sai_profile = sai_profile + ".backup"

    # Backup sai.profile
    if not dut.stat(path=backup_sai_profile)["stat"]["exists"]:
        logging.info("Backup %s to %s" % (sai_profile, backup_sai_profile))
        dut.command("cp %s %s" % (sai_profile, backup_sai_profile))

    # Extract the original settings in sai.profile
    original_settings = {}
    for line in dut.command("cat %s" % sai_profile)["stdout_lines"]:
        key, value = line.split("=")
        original_settings[key] = value

    # Merge the table size settings to the original settings. Overwrite the original value in case of conflict
    for key, value in table_size.items():
        original_settings[key] = value

    # Write the merged settings to sai.profile
    logging.info("Write new settings to %s" % sai_profile)
    content = ""
    for key, value in original_settings.items():
        content += "%s=%s\n" % (key, value)
    dut.copy(content=content, dest=sai_profile)


def configure_issu(dut, localhost, issu_status="disabled"):
    """
    @summary: Configure issu on DUT to specified status
    """
    dut_platform = dut.facts["platform"]
    hwsku = dut.facts["hwsku"]
    hwsku_digits = re.findall(r"\d+", hwsku)[0]
    sai_xml = "/usr/share/sonic/device/{}/{}/sai_{}.xml".format(dut_platform, hwsku, hwsku_digits)
    pattern = r"<issu-enabled>\d</issu-enabled>"

    if issu_status == "disabled":
        line = "<issu-enabled>0</issu-enabled>"
        dut.lineinfile(dest=sai_xml, regexp=pattern, line=line)
    elif issu_status == "enabled":
        line = "<issu-enabled>1</issu-enabled>"
        dut.lineinfile(dest=sai_xml, regexp=pattern, line=line)

    logging.info("Reboot the dut")
    reboot_task, reboot_res = dut.command("reboot", module_async=True)

    logging.info("Wait for DUT to go down")
    try:
        localhost.wait_for(host=dut.hostname, port=22, state="stopped", delay=10, timeout=300)
    except RunAnsibleModuleFail as e:
        logging.error("DUT did not go down, exception: " + repr(e))
        if reboot_task.is_alive():
            logging.error("Rebooting is not completed")
            reboot_task.terminate()
        logging.error("reboot result %s" % str(reboot_res.get()))
        assert False, "Failed to reboot the DUT"

    localhost.wait_for(host=dut.hostname, port=22, state="started", delay=10, timeout=300)

    logging.info("Wait until system is stable")
    wait_until(300, 30, dut.critical_services_fully_started)

    logging.info("Wait some extra time")
    time.sleep(180)


def crm_stats_found(dut):
    """
    @summary: Check whether CRM stats are available
    """
    return len(dut.get_crm_resources()["main_resources"].keys()) > 0


def compare_table_size(sai_settings, crm_stats):
    """
    @summary: Compare the CRM stats with the customized table size settings. Case failed if they do not match.
    """
    logging.info("SAI settings: %s" % json.dumps(sai_settings))
    logging.info("CRM stats: %s" % json.dumps(crm_stats))

    # TODO: FDB checking is skipped because of below bugs:
    # Bug SW #1829399: SAI profile: single hash table size calculation need to take IPv6 route and VID
    #                  into consideration.
    # Feature #1829380: SDK resource manager: expose min and max FDB entries for configure from outside
    # Need to enable FDB checking after the above bugs are fixed.
    tables = ["ipv4_route", "ipv6_route", "ipv4_neighbor", "ipv6_neighbor"]
    for table in tables:
        sai_setting = "SAI_%s_TABLE_SIZE" % table.upper()
        logging.info("*************ASSERT HERE***************")
        assert table in crm_stats.keys(), \
            "No CRM stats for %s, probably the table size settings are not accepted by SONiC." % table
        expected = sai_settings[sai_setting]
        actual = crm_stats[table]["used"] + crm_stats[table]["available"]
        # TODO: Used pytest.approx because of below bug:
        # Bug SW #1840858: IP neighbor used+available count is less than allocated number
        # Need to use exact compare after the bug is fixed
        assert expected == pytest.approx(actual, rel=0.001), \
            "Expected %s table size: %d, actual: %d" % (table, expected, actual)


def configure_table_size_and_check(table_size, dut, localhost, request):
    """
    @summary: Set table size and check CRM stats. Re-used by test cases.
    """
    logging.info("Set target table size in sai.profile")
    set_table_size(dut, table_size)

    logging.info("Reboot the dut")
    reboot_task, reboot_res = dut.command("reboot", module_async=True)

    logging.info("Wait for DUT to go down")
    try:
        localhost.wait_for(host=dut.hostname, port=22, state="stopped", delay=10, timeout=300)
    except RunAnsibleModuleFail as e:
        logging.error("DUT did not go down, exception: " + repr(e))
        if reboot_task.is_alive():
            logging.error("Rebooting is not completed")
            reboot_task.terminate()
        logging.error("reboot result %s" % str(reboot_res.get()))
        assert False, "Failed to reboot the DUT"

    logging.info("Wait for DUT to come back")
    localhost.wait_for(host=dut.hostname, port=22, state="started", delay=10, timeout=300)

    logging.info("Wait until system is stable")
    wait_until(300, 20, dut.critical_services_fully_started)

    logging.info("Set CRM polling interval to a short time")
    dut.command("crm config polling interval 3")

    logging.info("Add finalizer to ensure that CRM config interval is always restored")
    def restore_crm_interval():
        logging.info("Set CRM polling interval back to 300s")
        dut.command("crm config polling interval 300")
    request.addfinalizer(restore_crm_interval)

    logging.info("Wait some time for CRM stats to be available")
    time.sleep(60)

    logging.info("Read CRM stats")
    crm_stats = dut.get_crm_resources()["main_resources"]

    logging.info("Compare CRM stats with the configuration data")
    compare_table_size(table_size, crm_stats)


def test_typical_table_size(request, common_setup_teardown):
    """
    @summary: Test setting typical table size values and check the result.
    """
    testbed_devices = common_setup_teardown

    dut = testbed_devices["dut"]
    localhost = testbed_devices["localhost"]

    logging.info("Find out whether warm-reboot is supported on this platform")
    try:
        issu_enabled = "enabled" in dut.command("show platform mlnx issu")["stdout"]
    except:
        pytest.fail("Unable to get ISSU status, DUT is not in good state.")

    table_size = {
        "SAI_FDB_TABLE_SIZE": 32768,
        "SAI_IPV4_ROUTE_TABLE_SIZE": 102400,
        "SAI_IPV6_ROUTE_TABLE_SIZE": 16384,
        "SAI_IPV4_NEIGHBOR_TABLE_SIZE": 16384,
        "SAI_IPV6_NEIGHBOR_TABLE_SIZE": 8192
    }

    # If warm-reboot is supported (issu enabled), only half HW resources would be available
    # Need to use a different set of values for testing
    table_size_issu = {
        "SAI_FDB_TABLE_SIZE": 16384,
        "SAI_IPV4_ROUTE_TABLE_SIZE": 51200,
        "SAI_IPV6_ROUTE_TABLE_SIZE": 16384,
        "SAI_IPV4_NEIGHBOR_TABLE_SIZE": 8192,
        "SAI_IPV6_NEIGHBOR_TABLE_SIZE": 8192
    }

    logging.info("Configure table size and check")
    # Know issue: https://redmine.mellanox.com/issues/1800191
    # Bug SW #1800191: SAI key/value table size configuration failed if warm-reboot enabled

    if models[dut.facts["hwsku"]]["reboot"]["warm_reboot"]:
        logging.info("DUT supports warm reboot")
        if issu_enabled:

            logging.info("Disable warm-reboot")
            configure_issu(dut, localhost, issu_status="disabled")

            logging.info("Test table size configuration with warm-reboot disabled")
            configure_table_size_and_check(table_size, dut, localhost, request)

            # logging.info("Enable warm-reboot")
            # configure_issu(dut, localhost, issu_status="enabled")

            # TODO: Temporarily commented out because of Bug #1800191
            # logging.info("Test table size configuration with warm-reboot enabled")
            # configure_table_size_and_check(table_size_issu, dut, localhost, request)
        else:
            logging.info("Test table size configuration with warm-reboot disabled")
            configure_table_size_and_check(table_size, dut, localhost, request)

            # logging.info("Enable warm-reboot")
            # configure_issu(dut, localhost, issu_status="enabled")

            # TODO: Temporarily commented out because of Bug #1800191
            # logging.info("Test table size configuration with warm-reboot enabled")
            # configure_table_size_and_check(table_size_issu, dut, localhost, request)
    else:
        logging.info("DUT does not support warm reboot")

        logging.info("Test table size configuration with warm-reboot disabled")
        configure_table_size_and_check(table_size, dut, localhost, request)


def test_more_resources_for_ipv6(request, common_setup_teardown):
    """
    @summary: Configure more resources for IPv6 check the result.
    """
    testbed_devices = common_setup_teardown

    dut = testbed_devices["dut"]
    localhost = testbed_devices["localhost"]

    logging.info("Find out whether warm-reboot is supported on this platform")
    try:
        issu_enabled = "enabled" in dut.command("show platform mlnx issu")["stdout"]
    except:
        pytest.fail("Unable to get ISSU status, DUT is not in good state.")

    table_size = {
        "SAI_FDB_TABLE_SIZE": 32768,
        "SAI_IPV4_ROUTE_TABLE_SIZE": 32768,
        "SAI_IPV6_ROUTE_TABLE_SIZE": 25600,
        "SAI_IPV4_NEIGHBOR_TABLE_SIZE": 8192,
        "SAI_IPV6_NEIGHBOR_TABLE_SIZE": 16384
    }

    table_size_issu = {
        "SAI_FDB_TABLE_SIZE": 32768,
        "SAI_IPV4_ROUTE_TABLE_SIZE": 24576,
        "SAI_IPV6_ROUTE_TABLE_SIZE": 16384,
        "SAI_IPV4_NEIGHBOR_TABLE_SIZE": 8192,
        "SAI_IPV6_NEIGHBOR_TABLE_SIZE": 8192
    }

    logging.info("Configure table size and check")
    # Know issue: https://redmine.mellanox.com/issues/1800191
    # Bug SW #1800191: SAI key/value table size configuration failed if warm-reboot enabled

    if models[dut.facts["hwsku"]]["reboot"]["warm_reboot"]:
        logging.info("DUT supports warm reboot")
        if issu_enabled:
            logging.info("Disable warm-reboot")
            configure_issu(dut, localhost, issu_status="disabled")

            logging.info("Test table size configuration with warm-reboot disabled")
            configure_table_size_and_check(table_size, dut, localhost, request)

            # logging.info("Enable warm-reboot")
            # configure_issu(dut, localhost, issu_status="enabled")

            # TODO: Temporarily commented out because of Bug #1800191
            # logging.info("Test table size configuration with warm-reboot enabled")
            # configure_table_size_and_check(table_size_issu, dut, localhost, request)
        else:
            logging.info("Test table size configuration with warm-reboot disabled")
            configure_table_size_and_check(table_size, dut, localhost, request)

            # logging.info("Enable warm-reboot")
            # configure_issu(dut, localhost, issu_status="enabled")

            # TODO: Temporarily commented out because of Bug #1800191
            # logging.info("Test table size configuration with warm-reboot enabled")
            # configure_table_size_and_check(table_size_issu, dut, localhost, request)
    else:
        logging.info("DUT does not support warm reboot")

        logging.info("Test table size configuration with warm-reboot disabled")
        configure_table_size_and_check(table_size, dut, localhost, request)
