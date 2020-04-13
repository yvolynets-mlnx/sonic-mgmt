import pytest
import os
import re
import time
import json
import yaml
import logging

from common import reboot
from common.utilities import wait_until
from common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from check_critical_services import check_critical_services

BASE_DIR = os.path.dirname(os.path.realpath(__file__))

SUCCESS_CODE = 0
FAILURE_CODE = -1

FW_INSTALL_SUCCESS_LOG = "*.Firmware install ended * status=success*."
UNVALID_NAME_LOG = '.*Invalid value for "<component_name>"*.'
UNVALID_PATH_LOG = '.*Error: Invalid value for "fw_path"*.'
UNVALID_URL_LOG = '.*Error: Did not receive a response from remote machine. Aborting...*.'
INVALID_PLATFORM_SCHEMA_LOG = '.*Error: Failed to parse "platform_components.json": invalid platform schema*.'
INVALID_CHASSIS_SCHEMA_LOG = '.*Error: Failed to parse "platform_components.json": invalid chassis schema*.'
INVALID_COMPONENT_SCHEMA_LOG = '.*Error: Failed to parse "platform_components.json": invalid component schema*.'

logger = logging.getLogger(__name__)


class FwComponent(object):

    def get_name(self):
        """
        Get component name
        """
        raise NotImplemented

    def check_version(self, fw_version, comp_fw_status):
        """
        Check if component firmware version was updated as expected
        """
        raise NotImplemented

    def process_versions(self, dut, binaries_path):
        """
        Process latest/other component firmware versions
        """
        raise NotImplemented

    def update_fw(self, request):
        """
        Update component firmware
        """
        raise NotImplemented


class BiosComponent(FwComponent):

    def __init__(self, comp_name):
        self.__name = comp_name

    def get_name(self):
        return self.__name

    def check_version(self, fw_version, comp_fw_status):
        return comp_fw_status['version'].startswith(fw_version)

    def parse_version(self, files_path):
        fw_path = None
        fw_ver = None

        release_path = os.path.realpath(files_path)
        fw_ver = os.path.basename(os.path.dirname(release_path))
        fw_ver = fw_ver[::-1].replace('x', '0', 1)[::-1]

        for file_name in os.listdir(files_path):
            if file_name.endswith('.rom'):
                fw_path = os.path.join(files_path, file_name)
                break

        return fw_path, fw_ver

    def process_versions(self, dut, binaries_path):
        files_path = os.path.join(binaries_path, 'bios')
        platform_type = dut.facts['platform']
        fw_status = get_fw_status(dut)
        latest = '{}_latest'.format(platform_type)
        other = '{}_other'.format(platform_type)

        latest_fw_path = None
        latest_ver = None
        previous_fw_path = None
        previous_ver = None
        is_latest = False

        for file_name in os.listdir(files_path):
            if file_name.startswith(latest):
                latest_fw_path, latest_ver = self.parse_version(os.path.join(files_path, file_name))
                if fw_status['BIOS']['version'].startswith(latest_ver):
                    is_latest = True
            elif file_name.startswith(other):
                previous_fw_path, previous_ver = self.parse_version(os.path.join(files_path, file_name))

        versions = {
            'previous_firmware': previous_fw_path,
            'previous_version': previous_ver,
            'latest_firmware': latest_fw_path,
            'latest_version': latest_ver,
            'is_latest_installed': is_latest
        }
        logger.info(
            "{} parsed versions:\n{}".format(
                self.get_name(),
                json.dumps(versions, indent=4)
            )
        )

        return versions

    def update_fw(self, request):
        testbed_device = request.getfixturevalue("testbed_devices")
        localhost = testbed_device['localhost']
        dut = testbed_device['dut']

        logger.info("Complete {} firmware update: run cold reboot".format(self.get_name()))
        reboot_cmd = 'reboot'
        reboot_task, reboot_res = dut.command(reboot_cmd, module_ignore_errors=True, module_async=True)
        logger.info("Wait for DUT to go down")
        res = localhost.wait_for(host=dut.hostname, port=22, state='stopped', timeout=180, module_ignore_errors=True)
        if "failed" in res:
            try:
                logger.error("Wait for switch down failed, try to kill any possible stuck reboot task")
                pid = dut.command("pgrep -f '%s'" % reboot_cmd)['stdout']
                dut.command("kill -9 %s" % pid)
                reboot_task.terminate()
                logger.error("Result of command '%s': " + str(reboot_res.get(timeout=0)))
            except Exception as e:
                logger.error("Exception raised while cleanup reboot task and get result: " + repr(e))

        logger.info("Wait for DUT to come back")
        localhost.wait_for(host=dut.hostname, port=22, state='started', delay=10, timeout=300)

        logger.info("Wait until system is stable")
        wait_until(300, 30, dut.critical_services_fully_started)

        logger.info("Wait until system init is done")
        time.sleep(30)


class CpldComponent(FwComponent):

    def __init__(self, comp_name):
        self.__name = comp_name

    def get_name(self):
        return self.__name

    def check_version(self, fw_version, comp_fw_status):
        return comp_fw_status['version'].startswith(fw_version)

    def get_part_number(self, platform_type, files_path):
        cpld_pn = None

        conf_path = os.path.join(files_path, "{}/cpld_name_to_pn.yml".format(platform_type))
        with open(conf_path, "r") as config:
            cpld_name_to_pn_dict = yaml.safe_load(config)
            cpld_pn = cpld_name_to_pn_dict[self.__name]

        return cpld_pn

    def parse_version(self, platform_type, files_path, file_name, fw_status):
        fw_path = os.path.join(files_path, file_name)
        real_fw_path = os.path.realpath(fw_path)
        basename = os.path.basename(real_fw_path)
        name = os.path.splitext(basename)[0]
        rev = name.upper()

        # get CPLD part number
        cpld_pn = self.get_part_number(platform_type, files_path)
        if cpld_pn not in rev:
            raise RuntimeError(
                "Part number is not found: cpld={}, pn={}".format(
                    self.__name,
                    cpld_pn
                )
            )

        # parse CPLD version
        cpld_ver = rev.split(cpld_pn)[1]
        cpld_ver = cpld_ver[1:].split('_')[0]
        cpld_ver_major = cpld_ver[:5]
        cpld_ver_minor = cpld_ver[5:]

        # parse component version
        comp_pn = fw_status[self.__name]['version'].split('_')[0]
        comp_ver = fw_status[self.__name]['version'].split('_')[1]
        comp_ver_major = comp_ver[:5]
        comp_ver_minor = comp_ver[5:]

        # TODO: Provide better way for handling minor version support
        if int(comp_ver_minor) != 0:
            parsed_ver = "{}_{}{}".format(comp_pn, cpld_ver_major, cpld_ver_minor)
        else:
            parsed_ver = "{}_{}00".format(comp_pn, cpld_ver_major)

        return parsed_ver, cpld_ver_major == comp_ver_major

    def process_versions(self, dut, binaries_path):
        files_path = os.path.join(binaries_path, 'cpld')
        platform_type = dut.facts['platform']
        fw_status = get_fw_status(dut)
        latest = '{}_latest'.format(platform_type)
        other = '{}_other'.format(platform_type)

        latest_fw_path = None
        latest_ver = None
        previous_fw_path = None
        previous_ver = None
        is_previous = False
        is_latest = False

        for file_name in os.listdir(files_path):
            if file_name.startswith(latest):
                latest_ver, is_latest = self.parse_version(platform_type, files_path, file_name, fw_status)
                latest_fw_path = os.path.realpath(os.path.join(files_path, file_name))
            if file_name.startswith(other):
                previous_ver, is_previous = self.parse_version(platform_type, files_path, file_name, fw_status)
                previous_fw_path = os.path.realpath(os.path.join(files_path, file_name))

        versions = {
            'previous_firmware': previous_fw_path,
            'previous_version': previous_ver,
            'latest_firmware': latest_fw_path,
            'latest_version': latest_ver,
            'is_latest_installed': is_latest
        }
        logger.info(
            "{} parsed versions:\n{}".format(
                self.get_name(),
                json.dumps(versions, indent=4)
            )
        )

        return versions

    def update_fw(self, request):
        testbed_devices = request.getfixturevalue("testbed_devices")
        localhost = testbed_devices['localhost']
        dut = testbed_devices['dut']

        logger.info("Complete {} firmware update: run power cycle".format(self.get_name()))
        num_psu_cmd = "sudo psuutil numpsus"
        logger.info("Check how much PSUs DUT has")
        psu_num_out = dut.command(num_psu_cmd)
        psu_num = 0
        try:
            psu_num = int(psu_num_out['stdout'])
        except:
            pytest.fail("Unable to get the number of PSUs: cmd={}".format(num_psu_cmd))

        logger.info("Create PSU controller")
        psu_control = request.getfixturevalue("psu_controller")
        if psu_control is None:
            pytest.fail("Failed to create PSU controller: host={}".format(dut.hostname))
        all_psu_status = psu_control.get_psu_status()
        if all_psu_status:
            # turn off all psu
            for psu in all_psu_status:
                if psu['psu_on']:
                    logger.info("Turn off psu: id={}".format(psu['psu_id']))
                    psu_control.turn_off_psu(psu['psu_id'])
                    time.sleep(5)

            logger.info("Wait 30 sec to trigger {} firmware refresh".format(self.get_name()))
            time.sleep(30)

            all_psu_status = psu_control.get_psu_status()
            if all_psu_status:
                # turn on all psu
                for psu in all_psu_status:
                    if not psu['psu_on']:
                        logger.info("Turn on psu: id={}".format(psu['psu_id']))
                        psu_control.turn_on_psu(psu['psu_id'])
                        time.sleep(5)

        logger.info("Wait for DUT to come back")
        localhost.wait_for(host=dut.hostname, port=22, state='started', delay=10, timeout=300)

        logger.info("Wait until system is stable")
        wait_until(300, 30, dut.critical_services_fully_started)

        logger.info("Wait until system init is done")
        time.sleep(30)


def get_fw_status(dut):
    """
    Parse output of 'fwutil show status' and return the data
    """
    cmd = 'fwutil show status'
    result = dut.command(cmd)
    if result['rc'] != SUCCESS_CODE:
        pytest.fail("Failed to execute command: ={}".format(cmd))

    num_spaces = 2
    output_data = {}
    status_output = result['stdout']
    separators = re.split(r'\s{2,}', status_output.splitlines()[1])  # get separators
    output_lines = status_output.splitlines()[2:]

    for line in output_lines:
        data = []
        start = 0

        for sep in separators:
            curr_len = len(sep)
            data.append(line[start:start+curr_len].strip())
            start += curr_len + num_spaces

        component = data[2]
        output_data[component] = {
            'version': data[3],
            'desc': data[4]
        }

    return output_data


def set_default_boot(request):
    """
    Set current image as default
    """
    testbed_devices = request.getfixturevalue("testbed_devices")
    dut = testbed_devices['dut']

    image_facts = dut.image_facts()['ansible_facts']['ansible_image_facts']
    current_image = image_facts['current']

    logger.info("Set default boot: img={}".format(current_image))
    result = dut.command("sonic_installer set_default {}".format(current_image))
    if result['rc'] != SUCCESS_CODE:
        pytest.fail("Could not set default image {}. Aborting!".format(current_image))


def set_next_boot(request):
    """
    Set other available image as next.
    If there is no other available image, get it from user arguments
    """
    testbed_devices = request.getfixturevalue("testbed_devices")
    dut = testbed_devices['dut']

    image_facts = dut.image_facts()['ansible_facts']['ansible_image_facts']
    next_img = image_facts['next']
    if next_img == image_facts['current']:
        for img in image_facts['available']:
            if img != image_facts['current']:
                next_img = img
                break
    if next_img == image_facts['current']:
        try:
            second_image_path = request.config.getoption("--second_image_path")
            next_img = os.path.basename(second_image_path)
            dut.copy(src=second_image_path, dest='/home/admin')
            result = dut.command("sonic_installer install -y ./{}".format(next_img))
            if result['rc'] != SUCCESS_CODE:
                pytest.fail("Could not install image {}. Aborting!".format(next_img))
        except Exception as e:
            pytest.fail("Not enough images for this test. Aborting!")

    logger.info("Set next boot: img={}".format(next_img))
    result = dut.command("sonic_installer set_next_boot {}".format(next_img))
    if result['rc'] != SUCCESS_CODE:
        pytest.fail("Could not set image {} as next boot. Aborting!".format(next_img))


def reboot_to_image(request, image_type):
    """
    Reboot device to the specified image
    """
    testbed_devices = request.getfixturevalue("testbed_devices")
    dut = testbed_devices['dut']
    localhost = testbed_devices['localhost']

    logger.info("Set default image: img={}".format(image_type))
    result = dut.command("sonic_installer set_default {}".format(image_type))
    if result['rc'] != SUCCESS_CODE:
        pytest.fail("Failed to set default image: img={}".format(image_type))

    logger.info("Reboot the device")
    reboot_task, reboot_res = dut.command('reboot', module_async=True)

    try:
        logger.info("Wait for device to go down")
        localhost.wait_for(host=dut.hostname, port=22, state='stopped', delay=10, timeout=300)
    except Exception as err:
        reboot_task.terminate()
        logger.error("Failed to reboot the device: msg={}".format(reboot_res.get()))
        raise err

    logger.info("Wait for device to come back")
    localhost.wait_for(host=dut.hostname, port=22, state='started', delay=10, timeout=300)

    logger.info("Wait until system is stable")
    wait_until(300, 30, dut.critical_services_fully_started)

    logger.info("Wait until system init is done")
    time.sleep(30)

    image_facts = dut.image_facts()['ansible_facts']['ansible_image_facts']
    if image_facts['current'] != image_type:
        pytest.fail("Reboot to image failed: img={}".format(image_type))


def generate_components_file(dut, platform_components, comp_name, fw_path, fw_version):
    """
    Generate 'platform_components.json' file for positive test cases
    """
    fw_status = get_fw_status(dut)
    platform_type = dut.facts['platform']

    json_data = {}
    json_data['chassis'] = {}
    json_data['chassis'][platform_type] = {}
    json_data['chassis'][platform_type]['component'] = {}

    for comp in platform_components:
        json_data['chassis'][platform_type]['component'][comp] = {}
        if comp == comp_name:
            json_data['chassis'][platform_type]['component'][comp]['firmware'] = fw_path
            json_data['chassis'][platform_type]['component'][comp]['version'] = fw_version
            json_data['chassis'][platform_type]['component'][comp]['info'] = fw_status[comp]['desc']

    with open(os.path.join(BASE_DIR, "tmp_platform_components.json"), "w") as comp_file:
        json.dump(json_data, comp_file, indent=4)
        logger.info("Generated 'platform_components.json':\n{}".format(json.dumps(json_data, indent=4)))

    dst_path = "/usr/share/sonic/device/{}/platform_components.json".format(platform_type)
    src_path = os.path.join(BASE_DIR, "tmp_platform_components.json")
    dut.copy(src=src_path, dest=dst_path)


def generate_invalid_components_file(request, chassis_key, platform_type, is_valid_comp_structure):
    """
    Generate invlid 'platform_components.json' file for negative test cases
    """
    testbed_devices = request.getfixturevalue("testbed_devices")
    platform_components = request.getfixturevalue("platform_components")

    dut = testbed_devices['dut']
    fw_status = get_fw_status(dut)

    json_data = {}
    json_data[chassis_key] = {}
    json_data[chassis_key][platform_type] = {}
    json_data[chassis_key][platform_type]['component'] = {}

    for comp in platform_components:
        json_data[chassis_key][platform_type]['component'][comp] = {}
        json_data[chassis_key][platform_type]['component'][comp]['firmware'] = 'path/to/install'

        if not is_valid_comp_structure:
            json_data[chassis_key][platform_type]['component'][comp]['version'] = {}
            json_data[chassis_key][platform_type]['component'][comp]['version']['version'] = 'version/to/install'
        else:
            json_data[chassis_key][platform_type]['component'][comp]['version'] = 'version/to/install'

        json_data[chassis_key][platform_type]['component'][comp]['info'] = 'description'

    with open(os.path.join(BASE_DIR, "tmp_platform_components.json"), "w") as comp_file:
        json.dump(json_data, comp_file)
        logger.info("Generated invalid 'platform_components.json':\n{}".format(json.dumps(json_data, indent=4)))

    dst_path = "/usr/share/sonic/device/{}/platform_components.json".format(platform_type)
    src_path = os.path.join(BASE_DIR, "tmp_platform_components.json")
    dut.copy(src=src_path, dest=dst_path)


def execute_update_command(request, cmd, component_object, fw_version, expected_log):
    """
    Execute update command and verify that no errors occur
    """
    testbed_devices = request.getfixturevalue("testbed_devices")
    dut = testbed_devices['dut']

    loganalyzer = LogAnalyzer(ansible_host=dut, marker_prefix='acl')
    loganalyzer.load_common_config()

    try:
        loganalyzer.except_regex = [expected_log]
        with loganalyzer:
            logger.info("Execute update command: cmd={}".format(cmd))
            result = dut.command(cmd)
    except LogAnalyzerError as err:
        raise err

    if result['rc'] != SUCCESS_CODE:
        pytest.fail("Update failed: msg={}".format(result['stderr']))

    # complete fw update - cold reboot if BIOS, power cycle with 30 sec timeout if CPLD
    component_object.update_fw(request)

    # check output of show command
    fw_status = get_fw_status(dut)
    comp_fw_status = fw_status[component_object.get_name()]
    if not comp_fw_status['version']:
        pytest.fail("Installation didn't work. Aborting!")

    # verify updated firmware version
    logger.info("Verify firmware is updated: ver={}".format(fw_version))
    if not component_object.check_version(fw_version, comp_fw_status):
        pytest.fail(
            "Version check failed: current({}) != expected({})".format(
                comp_fw_status['version'],
                fw_version
            )
        )


def execute_invalid_update_command(dut, cmd, expected_log):
    """
    Execute invalid update command and verify that errors occur
    """
    result = dut.command(cmd, module_ignore_errors=True)
    if result['rc'] == SUCCESS_CODE:
        pytest.fail("Failed to get expected error code: rc={}".format(result['rc']))

    if not result['stderr'].find(expected_log):
        if not result['stdout'].find(expected_log):
            pytest.fail("Failed to find expected error message: msg={}".format(expected_log))


def update(request, cmd, component_object, remote_fw_path, local_fw_path, fw_version):
    """"
    Perform firmware update
    """
    testbed_devices = request.getfixturevalue("testbed_devices")
    dut = testbed_devices['dut']

    dut.copy(src=local_fw_path, dest=remote_fw_path)

    try:
        execute_update_command(
            request,
            cmd,
            component_object,
            fw_version,
            FW_INSTALL_SUCCESS_LOG
        )
    finally:
        dut.command("rm -f {}".format(remote_fw_path))


def update_from_current_image(request):
    """
    Update firmware from current image
    """
    logger.info("Update firmware from current image")

    testbed_devices = request.getfixturevalue("testbed_devices")
    platform_components = request.getfixturevalue("platform_components")
    component_object = request.getfixturevalue("component_object")
    component_firmware = request.getfixturevalue("component_firmware")
    dut = testbed_devices['dut']

    update_cmd = 'fwutil update -y --image=current'
    comp_name = component_object.get_name()

    if not component_firmware['is_latest_installed']:
        fw_name = os.path.basename(component_firmware['latest_firmware'])
        remote_fw_path = os.path.join('/tmp', fw_name)
        local_fw_path = component_firmware['latest_firmware']
        fw_version = component_firmware['latest_version']

        msg = "Install latest firmware for {}: version={}, path={}".format(
            component_object.get_name(),
            component_firmware['latest_version'],
            component_firmware['latest_firmware']
        )
        logger.info(msg)

        # install latest firmware
        generate_components_file(
            dut,
            platform_components,
            comp_name,
            remote_fw_path,
            fw_version
        )
        update(
            request,
            update_cmd,
            component_object,
            remote_fw_path,
            local_fw_path,
            fw_version
        )

    fw_name = os.path.basename(component_firmware['previous_firmware'])
    remote_fw_path = os.path.join('/tmp', fw_name)
    local_fw_path = component_firmware['previous_firmware']
    fw_version = component_firmware['previous_version']

    msg = "Install previous firmware for {}: version={}, path={}".format(
        component_object.get_name(),
        component_firmware['previous_version'],
        component_firmware['previous_firmware']
    )
    logger.info(msg)

    # install previous firmware
    generate_components_file(
        dut,
        platform_components,
        comp_name,
        remote_fw_path,
        fw_version
    )
    update(
        request,
        update_cmd,
        component_object,
        remote_fw_path,
        local_fw_path,
        fw_version
    )

def update_from_next_image(request):
    """
    Update firmware from next image
    """
    logger.info("Update firmware from next image")

    testbed_devices = request.getfixturevalue("testbed_devices")
    component_object = request.getfixturevalue("component_object")
    component_firmware = request.getfixturevalue("component_firmware")
    dut = testbed_devices['dut']

    set_next_boot(request)

    update_cmd = 'fwutil update -y --image=next'
    fw_version = component_firmware['latest_version']

    msg = "Install latest firmware for {}: version={}, path={}".format(
        component_object.get_name(),
        component_firmware['latest_version'],
        component_firmware['latest_firmware']
    )
    logger.info(msg)

    # install latest firmware
    execute_update_command(
        request,
        update_cmd,
        component_object,
        fw_version,
        FW_INSTALL_SUCCESS_LOG
    )
