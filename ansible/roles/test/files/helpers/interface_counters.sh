#!/bin/bash
IFS=$'\n'

RX_BPS_INDEX=0
NA_LEN=3

SHOW_COUNTERS=`show interfaces counters`
ERROR_MSG="The following fields contains 'N/A':"
FAILED=false

for l in $SHOW_COUNTERS
do
    if [[ "${l}" =~ "RX_BPS" ]] ;
    then
        rx_bps_index=$(echo $l | awk -v s=RX_BPS '{print index($l,s) + length("RX_BPS") - 4}')
        tx_bps_index=$(echo $l | awk -v s=TX_BPS '{print index($l,s) + length("TX_BPS") - 4}')
        rx_util_index=$(echo $l | awk -v s=RX_UTIL '{print index($l,s) + length("RX_UTIL") - 4}')
        tx_util_index=$(echo $l | awk -v s=TX_UTIL '{print index($l,s) + length("TX_UTIL") - 4}')
    fi

    if [[ "${l:$rx_bps_index:$NA_LEN}" = "N/A" ]] && [[ "$ERROR_MSG" != *"RX_BPS"* ]] ;
    then
        FAILED=true
        ERROR_MSG="$ERROR_MSG RX_BPS"
    fi
    if [[ ${l:$tx_bps_index:$NA_LEN} == "N/A" ]] && [[ "$ERROR_MSG" != *"TX_BPS"* ]] ;
    then
        FAILED=true
        ERROR_MSG="$ERROR_MSG TX_BPS"
    fi
    if [[ ${l:$rx_util_index:$NA_LEN} == "N/A" ]] && [[ "$ERROR_MSG" != *"RX_UTIL"* ]] ;
    then
        FAILED=true
        ERROR_MSG="$ERROR_MSG RX_UTIL"
    fi
    if [[ ${l:$tx_util_index:$NA_LEN} == "N/A" ]] && [[ "$ERROR_MSG" != *"TX_UTIL"* ]] ;
    then
        FAILED=true
        ERROR_MSG="$ERROR_MSG TX_UTIL"
    fi
done

if [[ $FAILED = true ]] ;
then
    echo $ERROR_MSG
    echo $SHOW_COUNTERS
    exit 1
fi
exit 0
