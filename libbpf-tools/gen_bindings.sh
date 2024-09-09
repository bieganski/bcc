#!/bin/bash

set -eux

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

pushd $SCRIPT_DIR

# Prerequsistes.
pip3 install --upgrade pip
pip3 install git+https://github.com/bieganski/ctypesgen
rm -rf gen
mkdir gen

# libbpf.h (together with workaround required by 'ctypesgen')
LIBPF_H=./bpftool/libbpf/src/libbpf.h
file -E $LIBPF_H
OUT=gen/libbpf.h
echo "#define __signed__ signed" > $OUT
cat $LIBPF_H  >> $OUT
sed -i 's/:0;/;/g' $OUT

# bpf.h
BPF_H=/usr/include/linux/bpf.h
file -E $BPF_H
OUT=gen/bpf.h
echo "#define __signed__ signed" > $OUT
cat $BPF_H >> $OUT
sed -i 's/:0;/;/g' $OUT

popd > /dev/null

ctypesgen -I `dirname $LIBPF_H` gen/libbpf.h -l ./libbpf.so.1 > gen/libbpf.py
ctypesgen gen/bpf.h -l ./libbpf.so.1 > gen/bpf.py