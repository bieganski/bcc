#!/bin/bash

set -eux

BPF_HEADER=./bpftool/libbpf/src/libbpf.h
file -E $BPF_HEADER

TEMP=libbpf_h__for_ctypesgen.h

pip3 install ctypesgen
# echo FOUND `grep -c ":0;" $BPF_HEADER` EMPTY UNIONS
# grep -v ":0;" $BPF_HEADER > $TEMP
echo "#define __signed__ signed" > $TEMP
sed 's/:0;/;/g' $BPF_HEADER >> $TEMP
ctypesgen -I `dirname $BPF_HEADER` $TEMP -l ./libbpf.so.1 > gen_bindings.py

# rm $TEMP

