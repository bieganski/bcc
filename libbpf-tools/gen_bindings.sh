#!/bin/bash

set -eux

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
pushd $SCRIPT_DIR

usage() {
    echo "Usage: $0 --libbpf-root <path>"
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --libbpf-root)
            LIBBPF_ROOT="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Check if LIBBPF_ROOT is set
if [[ -z "$LIBBPF_ROOT" ]]; then
    echo "Error: --libbpf-root is a required parameter."
    usage
fi

# Prerequsistes.

pip3 install --upgrade pip
pip3 install git+https://github.com/bieganski/ctypesgen

rm -rf gen
mkdir gen

# libbpf.h (together with workaround required by 'ctypesgen')
LIBBPF_C=$LIBBPF_ROOT/src/libbpf.c
LIBBPF_H=$LIBBPF_ROOT/src/libbpf.h
file -E $LIBBPF_H

# bpf.h
BPF_H=$LIBBPF_ROOT/include/uapi/linux/bpf.h
file -E $BPF_H

popd > /dev/null

ctypesgen -D__signed__=signed $BPF_H -l ./libbpf.so.1 > gen/bpf.py

# -l ./libbpf.so.1 \
ctypesgen \
-l ./libbpf.so.1 \
-D__signed__=signed \
"-D__builtin_constant_p(x)='1'" \
-I $LIBBPF_ROOT/include/ \
-I $LIBBPF_ROOT/include/uapi/ \
$LIBBPF_C $LIBBPF_H > gen/libbpf.py

wc -l gen/libbpf.py
./do_ast.py gen/libbpf.py gen/libbpf.py
wc -l gen/libbpf.py