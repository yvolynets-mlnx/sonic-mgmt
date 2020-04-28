import pytest
import os
import random
import yaml

from fwutil_helper import BiosComponent, CpldComponent
from fwutil_helper import set_default_boot, set_next_boot, reboot_to_image, generate_components_file

PLATFORM_COMP_PATH_TEMPLATE = '/usr/share/sonic/device/{}/platform_components.json'
BASE_DIR = os.path.dirname(os.path.realpath(__file__))

logger = logging.getLogger(__name__)

@pytest.fixture(scope='module')
def platform_components(request, testbed_devices):
    """
    Fixture that returns the platform components list
    according to the given config file.
    """
    dut = testbed_devices['dut']

    config_file = request.config.getoption("--config_file")
    # config file contains platform string identifier and components separated by ','.
    # e.g.: x86_64-mlnx_msn2010-r0: BIOS,CPLD
    conf_path = os.path.join(BASE_DIR, config_file)
    with open(conf_path, "r") as config:
        platforms_dict = yaml.safe_load(config)
        platform_type = dut.facts['platform']
        components = platforms_dict[platform_type]

    yield components.split(",")


@pytest.fixture(scope='function')
def component_object(platform_components):
    """
    Fixture that returns arbitrary firmware component object
    """
    comp_name = random.choice(platform_components)

    pattern = re.compile('^[A-Za-z]+')
    result = pattern.search(comp_name.capitalize())
    if not result:
        pytes.fail("Failed to detect component type: name={}".format(comp_name))

    yield globals()[result.group(0).lower().capitalize() + 'Component'](comp_name)


@pytest.fixture(scope='function')
def component_firmware(request, testbed_devices, component_object):
    """
    Fixture that returns component firmware paths
    """
    dut = testbed_devices['dut']

    binaries_path = request.config.getoption('--binaries_path')
    if not binaries_path:
        pytest.fail("Missing arguments: --binaries_path")

    yield component_object.process_versions(dut, binaries_path)


@pytest.fixture(scope='function')
def skip_if_no_update(component_object, component_firmware):
    """
    Fixture that skips test execution in case no firmware updates: previous = latest
    """
    if component_firmware['latest_version'] == component_firmware['previous_version']:
        pytest.skip(
            "Latest {} firmware is already installed".format(
                component_object.get_name()
            )
        )


@pytest.fixture(scope='function')
def backup_platform_file(testbed_devices):
    """
    Backup the original 'platform_components.json' file
    """
    dut = testbed_devices['dut']

    platform_type = dut.facts['platform']
    platform_comp_path = '/usr/share/sonic/device/' + platform_type + '/platform_components.json'
    backup_path = os.path.join(BASE_DIR, "platform_component_backup.json")
    res = dut.fetch(src=platform_comp_path, dest=backup_path, flat='yes')

    yield

    dut.copy(src=backup_path, dest=platform_comp_path)


@pytest.fixture(scope='function')
def setup_images(request, testbed_devices, platform_components, component_object, component_firmware):
    """"
    Setup part of 'update from next image test' case.
    Backup both images files and generate new json files
    """
    dut = testbed_devices['dut']

    set_default_boot(request)
    set_next_boot(request)

    image_info = dut.image_facts()['ansible_facts']['ansible_image_facts']
    current_image = image_info['current']
    next_image = image_info['next']
    logger.info("Configure images (setup): current={}, next={}".format(current_image, next_image))

    platform_type = dut.facts['platform']
    platform_comp_path = PLATFORM_COMP_PATH_TEMPLATE.format(platform_type)

    # backup current image platform file
    current_backup_path = os.path.join(BASE_DIR, "current_platform_component_backup.json")
    dut.fetch(src=platform_comp_path, dest=current_backup_path, flat="yes")

    # reboot to next image
    logger.info("Reboot to next image: img={}".format(next_image))
    reboot_to_image(request, image_type=next_image)

    # backup next-image platform file
    next_backup_path = os.path.join(BASE_DIR, "next_platform_component_backup.json")
    dut.fetch(src=platform_comp_path, dest=next_backup_path, flat="yes")

    # generate component file for the next image
    comp_name = component_object.get_name()
    fw_name = os.path.basename(component_firmware['latest_firmware'])
    fw_path = os.path.join('/home/admin', fw_name)
    fw_version = component_firmware['latest_version']
    generate_components_file(
        dut,
        platform_components,
        comp_name,
        fw_path,
        fw_version
    )
    # copy fw to dut (next image)
    dut.copy(src=component_firmware['latest_firmware'], dest=fw_path)

    # reboot to first image
    logger.info("Reboot to current image: img={}".format(current_image))
    reboot_to_image(request, image_type=current_image)

    yield

    # teardown
    new_image_info = dut.image_facts()['ansible_facts']['ansible_image_facts']
    new_current_image = new_image_info['current']
    new_next_image = new_image_info['next']
    logger.info("Configure images (teardown): current={}, next={}".format(new_current_image, new_next_image))

    if new_current_image == next_image:
        dut.command("rm -f {}".format(fw_path))
        dut.copy(src=next_backup_path, dest=PLATFORM_COMP_PATH_TEMPLATE.format(platform_type))
        reboot_to_image(request, image_type=current_image)
        dut.copy(src=current_backup_path, dest=PLATFORM_COMP_PATH_TEMPLATE.format(platform_type))
    else:
        dut.copy(src=current_backup_path, dest=PLATFORM_COMP_PATH_TEMPLATE.format(platform_type))
        reboot_to_image(request, image_type=next_image)
        dut.command("rm -f {}".format(fw_path))
        dut.copy(src=next_backup_path, dest=PLATFORM_COMP_PATH_TEMPLATE.format(platform_type))
        reboot_to_image(request, image_type=current_image)
