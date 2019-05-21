## Overview

The puspose is to test hardware resuorces consumed by the device. Hardware resources are: CPU, RAM, HDD.

## Scope
The test is targeting a running SONiC system with functioning configuration according to testbed setup.
The purpose is to test device CPU, RAM and HDD resources consumption are in expected range.

## Quality Objective
- Ensure CPU consumption by the applications does not exceed limit
- Ensure RAM consumption by the applications does not exceed limit
- Ensure the partition mounted to the "/" root folder of the HDD do not exceed limit space

## Testbed
T0, T1, T1-lag, PTF32

## Note:
The boundary values of resuorce consumption need to be agreed.

## Test cases

### 1. Test RAM consumption

Description:
Verify that RAM consumption on the device is in the expected range.

Test Steps:

- Run "show system-memory" command
- Convert used RAM value to the percentage
- Compare obtained value with defined RAM treshold

- For failed test run the following commands and display output:
  - docker stats --all --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"
  - ps aux --sort rss

### Pass/Fail Criteria

- "show system-memory" should output these fields: total, used, free, shared, buff/cache, available
```sh
              total        used        free      shared  buff/cache   available
Mem:           7936        1956        4064          55        1915        5655
Swap:             0           0           0
```

- 'used' value of the above command should be less then or equal to the RAM treshold

## Note:
Need to define treshold for used RAM

### 2. Test CPU consumption

Description:
Verify that CPU consumption on the device is in the expected range.

Test steps:

- Run "uptime" command
- Get load average for 5 minutes
- Convert CPU load average to the percentage
- Compare obtained value with defined for used CPU treshold

- For failed test run the following commands and display output:
  - docker stats --all --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"
  - ps aux --sort %cpu

### Pass/Fail criteria

- CPU load average obtained by calling "uptime" should be less then or equal to the defined CPU treshold

## Note:
Need to define CPU types and used CPU threshold for each specific CPU type (in percentage).

### 3. Test HDD free space

Description:
On the switch device currently /dev/sda3 partition is mounted to the "/" root directory.
Verify that available space in the root directory is in expected range.

Test steps:
- Run "df -hm /" command
- Get "Available" value
- Compare obtained value with defined treshold for HDD free space

- For failed test run the following commands and display output:
  - df -h --total /*

### Pass/Fail criteria

- Available free space in "/" directory should be more then or equal to the defined HDD free space

## Note:
Need to define treshold for free HDD space of "/" root directory.
