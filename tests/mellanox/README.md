# Configurable Table Size Testing

## Feature Description
Configurable table size is a Mellanox specific SONiC feature. The ASIC has hardware resources that can be allocated for different tables, the tables that support size configuration:
* FDB Table
* IPv4 Route Table
* IPv6 Route Table
* IPv4 Neighbor Table
* IPv6 Neighbor Table

Before the configurable table size feature was implemented, all the size of the tables are kind of hard-coded. With this feature, user can configure the size of each table individually in the sai profile `/usr/share/sonic/device/<platform>/<hw_sku>/sai.profile`. For example:

```
admin@mtbc-sonic-03-2700:~$ cat /usr/share/sonic/device/x86_64-mlnx_msn2700-r0/ACS-MSN2700/sai.profile
SAI_INIT_CONFIG_FILE=/usr/share/sonic/hwsku/sai_2700.xml
SAI_FDB_TABLE_SIZE=32768
SAI_IPV4_ROUTE_TABLE_SIZE=102400
SAI_IPV6_ROUTE_TABLE_SIZE=16384
SAI_IPV4_NEIGHBOR_TABLE_SIZE=16384
SAI_IPV6_NEIGHBOR_TABLE_SIZE=8192
```

Reboot is required for the new settings to take effect. After reboot, then we can check the resource allocation using the `crm show resources all` command.

```
admin@mtbc-sonic-03-2700:~$ crm show resources all

Resource Name           Used Count    Available Count
--------------------  ------------  -----------------
ipv4_route                    6474              95926
ipv6_route                    6444               9940
ipv4_nexthop                    24              36753
ipv6_nexthop                    24              36753
ipv4_neighbor                   24              16360
ipv6_neighbor                   24               8168
nexthop_group_member            39              36753
nexthop_group                    4              36753
fdb_entry                        0               8179


Stage    Bind Point    Resource Name      Used Count    Available Count
-------  ------------  ---------------  ------------  -----------------
INGRESS  PORT          acl_group                  16                375
INGRESS  PORT          acl_table                   3                395
INGRESS  LAG           acl_group                   8                375
INGRESS  LAG           acl_table                   0                395
INGRESS  VLAN          acl_group                   0                375
INGRESS  VLAN          acl_table                   0                395
INGRESS  RIF           acl_group                   0                375
INGRESS  RIF           acl_table                   0                395
INGRESS  SWITCH        acl_group                   0                375
INGRESS  SWITCH        acl_table                   0                395
EGRESS   PORT          acl_group                   0                375
EGRESS   PORT          acl_table                   0                395
EGRESS   LAG           acl_group                   0                375
EGRESS   LAG           acl_table                   0                395
EGRESS   VLAN          acl_group                   0                  0
EGRESS   VLAN          acl_table                   0                  0
EGRESS   RIF           acl_group                   0                375
EGRESS   RIF           acl_table                   0                395
EGRESS   SWITCH        acl_group                   0                375
EGRESS   SWITCH        acl_table                   0                395


Table ID    Resource Name    Used Count    Available Count
----------  ---------------  ------------  -----------------
```

The used count plus available count of each item should be equal to the settings in sai.profile. Expected:
* fdb_entry used + available = SAI_FDB_TABLE_SIZE
* ipv4_route used + available = SAI_IPV4_TABLE_SIZE
* ipv6_route used + available = SAI_IPV4_TABLE_SIZE
* ipv4_neighbor used + available = SAI_IPV4_NEIGHBOR_TABLE_SIZE
* ipv6_neighbor used + available = SAI_IPV6_NEIGHBOR_TABLE_SIZE

If warm-reboot is supported (issu enabled), only half HW resources would be available. For this case, we need to use a different set of values for testing.

## Test Cases
In this testing, we have 3 test cases:
* test_typical_table_size
* test_more_resources_for_ipv6
* test_less_fdb_resources

For each of the test case, if the tested platform does not support ISSU, only one set of settings for ISSU disabled will be covered. If the tested platform supports ISSU, two sets of settings will be covered, one for ISSU disabled, one for ISSU enabled.

The basic flow of each test case:
* Set ISSU status disabled
* Set table size configuration in sai.profile.
* Reboot
* Check result using `crm show resources all`
* If the tested platform supports ISSU:
  * Set ISSU enabled
  * Set table size configuration in sai.profile.
  * Reboot
  * Check result using `crm show resources all`

The common_setup_teardown is to backup sai.profile before testing and recover it after testing.

| Scenario                                    | SAI_FDB_TABLE_SIZE | SAI_IPV4_ROUTE_TABLE_SIZE | SAI_IPV6_ROUTE_TABLE_SIZE | SAI_IPV4_NEIGHBOR_TABLE_SIZE | SAI_IPV6_NEIGHBOR_TABLE_SIZE |
| ------------------------------------------- | ------------------ | ------------------------- | ------------------------- | ---------------------------- | ---------------------------- |
| test_typical_table_size, ISSU disabled      | 32768              | 102400                    | 16384                     | 16384                        | 8192                         |
| test_typical_table_size, ISSU enabled       | 16384              | 51200                     | 16384                     | 8192                         | 8192                         |
| test_more_resources_for_ipv6, ISSU disabled | 32768              | 32768                     | 25600                     | 8192                         | 16384                        |
| test_more_resources_for_ipv6, ISSU enabled  | 32768              | 24576                     | 16384                     | 8192                         | 8192                         |
| test_less_fdb_resources, ISSU disabled      | 10240              | 32768                     | 25600                     | 8192                         | 16384                        |
| test_less_fdb_resources, ISSU enabled       | 5120               | 24576                     | 16384                     | 8192                         | 8192                         |

## Known Issues

By the time of writing, there are some know issues:
* Bug SW #1800191: SAI key/value table size configuration failed if warm-reboot enabled
* Bug SW #1978577: SONiC failed to init switch with a combination table size set
* Bug SW #1829399: SAI profile: single hash table size calculation need to take IPv6 route and VID into consideration

Because of the known issues, some test cases are commented out in the script. We need to uncomment the tests after the known issues are fixed.
