#!/usr/bin/python

import re
import ipaddr
from ansible.module_utils.basic import *

DOCUMENTATION = '''
module:  fib_facts
version_added:  "1.0"
short_description: Generate fib facts as dictionary where key is a network prefix and value is a list of nexthops
Options:
    - option-name: fib
      description: a path to a fib file
      required: True
      Default: None
'''

EXAMPLES = '''
- name: Generate FIB facts
  fib_facts:
    fib: /tmp/fib_info.txt
  connection: local
'''


def get_peer_from_iface_idx(port_index, ipv6=False):
    """ Return DUT port name from given port_index
    (Currently hardcoded logic for T1)
    TODO: get peer address from bgp
    """

    if ipv6:
        return 'fc00::{:x}'.format(port_index * 4 + 2)
    else:
        return '10.0.0.{}'.format(port_index * 2 + 1)


def parse_fib_file(fib_path):
    """Gather fib information from fib_info file"""

    result = dict()
    result["fib"] = dict()

    with open(fib_path, 'r') as fib:
        for line in fib.readlines():
            prefix, out_ports = line.split(' ', 1)
            out_ports = [int(port) for port in re.findall('\d+', out_ports)]

            route_subnet = ipaddr.IPNetwork(prefix)
            available_peers = []
            for port in out_ports:
                if route_subnet.version == 4:
                    available_peers += [get_peer_from_iface_idx(port)]
                if route_subnet.version == 6:
                    available_peers += [get_peer_from_iface_idx(port, ipv6=True)]

            result["fib"][prefix] = available_peers

    return result


def main():
    module = AnsibleModule(
        argument_spec=dict(
            fib=dict(required=True, type='str'),
          ),
        supports_check_mode=False
        )

    p = module.params

    try:
        res = parse_fib_file(p['fib'])
    except:
        err = str(sys.exc_info())
        module.fail_json(msg='Error: %s' % err)
    module.exit_json(ansible_facts=res)


if __name__ == '__main__':
    main()
