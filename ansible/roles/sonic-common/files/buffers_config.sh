#!/bin/bash

declare -r BUFFERS_TEMPLATE="/usr/share/sonic/templates/buffers_config.j2"
declare -r BUFFERS_PATCH="/tmp/buffers_patch.j2"

cat > ${BUFFERS_PATCH} <<EOL
{%- if DEVICE_NEIGHBOR_METADATA is not defined %}
{%- set DEVICE_NEIGHBOR_METADATA = dict() %}
{%- endif -%}

EOL

sed -i -e "1 e cat ${BUFFERS_PATCH}" ${BUFFERS_TEMPLATE}
