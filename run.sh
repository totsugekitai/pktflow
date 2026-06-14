#!/bin/bash
set -euo pipefail

binds=()
config_file='pktflow.toml'
is_release="false"
is_daemon="false"
LOG=${RUST_LOG:-info}

short_optstr='b:c:dh'
long_optstr='bind:,config:,daemon,release,help'
progname="$0"

### Usage
help() {
    echo "$progname [options]"
    echo "Options:"
    echo "  -b,--bind <PCI address>    Bind NIC to DPDK."
    echo "                             This option can be specified multiple times."
    echo "                             <PCI address> is, for example, 0000:02:00.1"
    echo "  -c,--config <Config file>  Specify a config file formatted TOML."
    echo "                             If don't use this option, default \"pktflow.toml\"."
    echo "  -d,--daemon                Run as a daemon driven by the REST API."
    echo "  --release                  Use release build."
    echo "  -h,--help                  Help message."
}

### Parse options

OPTS=$(getopt -o "$short_optstr" -l "$long_optstr" -n "$progname" -- "$@")

eval set -- "$OPTS"
unset OPTS

while true; do
    case "$1" in
        '-b'|'--bind')
            binds+=("$2")
            shift 2
            ;;
        '-c'|'--config')
            config_file="$2"
            shift 2
            ;;
        '-d'|'--daemon')
            is_daemon="true"
            shift
            ;;
        '--release')
            is_release="true"
            shift
            ;;
        '-h'|'--help')
            help
            exit 0
            ;;
        '--')
            shift
            break
            ;;
    esac
done

### Execute program

sudo modprobe vfio-pci
echo 2048 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages > /dev/null

for bind in ${binds[@]}; do
    sudo dpdk-devbind.py -b vfio-pci "$bind"
done

subcmd=''
if [ "$is_daemon" = "true" ]; then
    subcmd='daemon '
fi

if [ "$is_release" = "true" ]; then
    sudo RUST_LOG=$LOG ./target/release/pktflow $subcmd"$config_file"
else
    sudo bash -c "ulimit -c unlimited && sysctl -w fs.suid_dumpable=1 > /dev/null && RUST_BACKTRACE=1 RUST_LOG=$LOG ./target/debug/pktflow $subcmd$config_file"
fi
