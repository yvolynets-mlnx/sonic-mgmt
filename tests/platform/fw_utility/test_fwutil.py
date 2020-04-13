import pytest
import os
import logging

from fwutil_helper import UNVALID_NAME_LOG, UNVALID_PATH_LOG, UNVALID_URL_LOG
from fwutil_helper import INVALID_PLATFORM_SCHEMA_LOG, INVALID_CHASSIS_SCHEMA_LOG, INVALID_COMPONENT_SCHEMA_LOG
from fwutil_helper import get_fw_status, update, execute_invalid_update_command, generate_invalid_components_file
from fwutil_helper import update_from_current_image, update_from_next_image

logger = logging.getLogger(__name__)


def test_show_positive(testbed_devices, platform_components):
    """
    Verify firmware status is valid
    Note: use vendor specific platform config file
    """
    dut = testbed_devices['dut']
    fw_status = get_fw_status(dut)

    logger.info("Verify platform schema")
    for comp in platform_components:
        if comp not in fw_status:
            pytest.fail("Missing component {}".format(comp))


@pytest.mark.disable_loganalyzer
def test_install_positive(request, skip_if_no_update, testbed_devices, component_object, component_firmware):
    """
    Verify firmware install from local path
    """
    dut = testbed_devices['dut']

    install_cmd_tmplt = "fwutil install chassis component {} fw -y {}"

    if not component_firmware['is_latest_installed']:
        fw_name = os.path.basename(component_firmware['latest_firmware'])
        remote_fw_path = os.path.join('/tmp', fw_name)
        local_fw_path = component_firmware['latest_firmware']
        fw_version = component_firmware['latest_version']
        install_cmd = install_cmd_tmplt.format(component_object.get_name(), remote_fw_path)

        msg = "Install latest firmware for {}: version={}, path={}".format(
            component_object.get_name(),
            component_firmware['latest_version'],
            component_firmware['latest_firmware']
        )
        logger.info(msg)

        # install latest firmware
        update(
            request,
            install_cmd,
            component_object,
            remote_fw_path,
            local_fw_path,
            fw_version
        )
    else:
        fw_name = os.path.basename(component_firmware['previous_firmware'])
        remote_fw_path = os.path.join('/tmp', fw_name)
        local_fw_path = component_firmware['previous_firmware']
        fw_version = component_firmware['previous_version']
        install_cmd = install_cmd_tmplt.format(component_object.get_name(), remote_fw_path)

        msg = "Install previous firmware for {}: version={}, path={}".format(
            component_object.get_name(),
            component_firmware['previous_version'],
            component_firmware['previous_firmware']
        )
        logger.info(msg)

        # install previous firmware
        update(
            request,
            install_cmd,
            component_object,
            remote_fw_path,
            local_fw_path,
            fw_version
        )

        fw_name = os.path.basename(component_firmware['latest_firmware'])
        remote_fw_path = os.path.join('/tmp', fw_name)
        local_fw_path = component_firmware['latest_firmware']
        fw_version = component_firmware['latest_version']
        install_cmd = install_cmd_tmplt.format(component_object.get_name(), remote_fw_path)

        msg = "Install latest firmware for {}: version={}, path={}".format(
            component_object.get_name(),
            component_firmware['latest_version'],
            component_firmware['latest_firmware']
        )
        logger.info(msg)

        # install latest firmware
        update(
            request,
            install_cmd,
            component_object,
            remote_fw_path,
            local_fw_path,
            fw_version
        )


@pytest.mark.disable_loganalyzer
def test_install_negative(request, testbed_devices, component_object, component_firmware):
    """
    Verify that firmware utility is able to handle
    invalid install flow as expected
    """
    dut = testbed_devices['dut']
    comp_name = component_object.get_name()
    fw_path = component_firmware['latest_firmware']

    # invalid component name
    logger.info("Verify invalid component name case")
    cmd = "fwutil install chassis component {} fw -y {}".format('UNVALID_FW_NAME', fw_path)
    execute_invalid_update_command(dut, cmd, UNVALID_NAME_LOG)

    # invalid path
    logger.info("Verify invalid path case")
    cmd = "fwutil install chassis component {} fw -y {}".format(comp_name, '/this/is/invalid/path')
    execute_invalid_update_command(dut, cmd, UNVALID_PATH_LOG)

    # invalid url
    logger.info("Verify invalid url case")
    cmd = "fwutil install chassis component {} fw -y {}".format(comp_name, 'http://this/is/invalid/url')
    execute_invalid_update_command(dut, cmd, UNVALID_URL_LOG)


@pytest.mark.disable_loganalyzer
def test_update_positive(request, skip_if_no_update, testbed_devices, setup_images):
    """
    Verify firmware update from current/next image
    """
    update_from_current_image(request)
    update_from_next_image(request)


@pytest.mark.disable_loganalyzer
def test_update_negative(request, testbed_devices, backup_platform_file):
    """
    Verify that firmware utility is able to handle
    invalid 'platform_components.json' file as expected
    """
    dut = testbed_devices['dut']
    platform_type = dut.facts['platform']
    cmd = 'fwutil update -y'

    # invalid platform schema
    logger.info("Verify invalid platform schema case")
    generate_invalid_components_file(
        request,
        chassis_key='INVALID_CHASSIS',
        platform_type=platform_type,
        is_valid_comp_structure=True
    )
    execute_invalid_update_command(dut, cmd, INVALID_PLATFORM_SCHEMA_LOG)

    # invalid chassis schema
    logger.info("Verify invalid chassis schema case")
    generate_invalid_components_file(
        request,
        chassis_key='chassis',
        platform_type='INVALID_PLATFORM',
        is_valid_comp_structure=True
    )
    execute_invalid_update_command(dut, cmd, INVALID_CHASSIS_SCHEMA_LOG)

    # invalid components schema
    logger.info("Verify invalid components schema case")
    generate_invalid_components_file(
        request,
        chassis_key='chassis',
        platform_type=platform_type,
        is_valid_comp_structure=False
    )
    execute_invalid_update_command(dut, cmd, INVALID_COMPONENT_SCHEMA_LOG)
