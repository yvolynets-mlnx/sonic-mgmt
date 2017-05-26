#!/bin/bash


onie_user=root
onie_pass=

serial="ssh -l rcon:7030 10.224.2.81"
ip_addr="arc-switch1027"

usage() {
    cat << EOF
$0 -p PATH_TO_IMAGES|-u URL -s SERIAL

Deploy ONIE image to device

OPTIONS
    -p path to image.
    -u image URL.
    -s command to connect to device serial console.
    -a management interface IP address.
EOF
}

path=
url=
serial=
address=

while getopts "p:u:s:a:" opt; do
    case $opt in
        p)
            path=${OPTARG}
            ;;
        u)
            url=${OPTARG}
            ;;
        s)
            serial=${OPTARG}
            ;;
        a)
            address=${OPTARG}
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done

if ([ -n "$path" ] && [ -n "$url" ]) || ([ -z "$path" ] && [ -z "$url" ]); then
    echo "Error: Path OR URL should be specified."
    usage
    exit 1
fi

if [ -z "$serial" ]; then
    echo "Error: Serial console command is not specified."
    usage
    exit 1
fi

if [ -z "$address" ]; then
    echo "Error: Mgmt IP address is not specified."
    usage
    exit 1
fi

if [[ "$serial" =~ "telnet" ]]; then
    telnet_login="
       expect \"*login:*\"
       sleep 1
       send -- \"admin\n\r\"
       expect \"Password:*\"
       sleep 1
       send -- \"admin\n\r\"
       sleep 1
       send \"\n\" 
    "
fi

expect <<- DONE
    set timeout -1

    spawn $serial
    match_max 100000

    $telnet_login

    expect "*GNU GRUB*ONIE*"
    sleep 2
    send -- "v"
    sleep 1
    send -- "v"
    sleep 1
    send -- "\n\r"
    expect "*GNU GRUB*ONIE: Rescue*"
    sleep 2
    send -- "v"
    sleep 1
    send -- "\r"
    sleep 1
    expect "Please press Enter to activate this console*"
    send -- "\n\r"
    sleep 1
DONE

temp_dir=

if [ -n "$url" ]; then
    temp_dir=`mktemp -d`
    wget $url -O $temp_dir/image
    path=$temp_dir/image
fi

chmod +x $path
scp $path $onie_user@$address:/image

if [ -n "$temp_dir" ];then
    rm -f $temp_dir
fi

expect <<- DONE
    set timeout -1

    spawn $serial
    match_max 100000

    $telnet_login

    send -- "chmod +x /image\n\r"

    send -- "yes | /image\n\r"
    expect "ONIE*#"

    send -- "reboot\n\r"
    expect "*login:"
DONE
