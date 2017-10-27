#!/usr/bin/env python

import re
import os
import traceback
import subprocess
from operator import itemgetter
from itertools import groupby
from collections import defaultdict

DOCUMENTATION = '''
module: port_speed.py
Ansible_version_added:  2.0.0.2
short_description:   Find SONiC device port speed mapping if there is speed mapping
Description:
        Minigraph file is using SONiC device speed to describe the interface name, it's vendor and and hardware platform dependent
        This module is used to find the correct port_config.ini for the hwsku and return Ansible ansible_facts.port_speed
        The definition of this mapping is specified in http://github.com/azure/sonic-buildimage/device
        You should build docker-sonic-mgmt from sonic-buildimage and run Ansible from sonic-mgmt docker container 
    Input:
        hwsku

    Return Ansible_facts:
    port_speed:  SONiC interface name or SONiC interface speed if speed is available

'''

EXAMPLES = '''
    - name: get hardware interface speed
      port_speed: hwsku='ACS-MSN2700'
'''

FILE_PATH = '/usr/share/sonic/device'
PORTMAP_FILE = 'port_config.ini'

class SonicPortAliasMap():
    """
    Retrieve SONiC device interface port speed mapping

    """
    def __init__(self, hwsku):
        self.filename = ''
        self.hwsku = hwsku
        self.portmap = []
        return

    def findfile(self):
        for (rootdir, dirnames, filenames) in os.walk(FILE_PATH):
            if self.hwsku in rootdir and len(dirnames) == 0 and PORTMAP_FILE in filenames:
                self.filename = rootdir+'/'+PORTMAP_FILE

    def get_portmap(self):
        self.findfile()
        if self.filename == '':
            raise Exception("Something wrong when trying to find the portmap file, either the hwsku is not available or file location is not correct")

        with open(self.filename) as f:
            lines = f.readlines()

        alias_idx = 0
        speed_idx = 0

        for  line in lines:
            if line.startswith('#'):
                if 'speed' in line:
                    speed_idx = 2
                if 'alias' in line:
                    alias_idx = 2
                    speed_idx = 3
                continue

            if 'Ethernet' in line:
                mapping = line.split()
                speed = ""
                if ((len(mapping) - 1) >= speed_idx) and (speed_idx != 0):
                    speed = mapping[speed_idx]
                self.portmap.append(speed)

        return

def main():
    module = AnsibleModule(
        argument_spec=dict(
            hwsku=dict(required=True, type='str')
        ),
        supports_check_mode=False
    )
    m_args = module.params
    try:
        allmap = SonicPortAliasMap(m_args['hwsku'])
        allmap.get_portmap()
        module.exit_json(ansible_facts={'port_speed': allmap.portmap})
    except (IOError, OSError):
        module.fail_json(msg=allmap.portmap)
    except Exception:
        module.fail_json(msg=allmap.portmap)

from ansible.module_utils.basic import *
if __name__ == "__main__":
    main()
