#!/bin/bash

set -eux

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

pushd $SCRIPT_DIR

# Prerequsistes.

# XXX
# pip3 install --upgrade pip
# pip3 install git+https://github.com/bieganski/ctypesgen

rm -rf gen
mkdir gen

# libbpf.h (together with workaround required by 'ctypesgen')
LIBBPF_C=/home/m.bieganski/github/libbpf/src/libbpf.c
LIBBPF_H=/home/m.bieganski/github/libbpf/src/libbpf.h
file -E $LIBBPF_H
# OUT=gen/libbpf.h
# echo "#define __signed__ signed" > $OUT
# cat $LIBPF_H  >> $OUT
# sed -i 's/:0;/;/g' $LIBBPF_H

# bpf.h
BPF_H=/home/m.bieganski/github/libbpf/include/uapi/linux/bpf.h
file -E $BPF_H
OUT=gen/bpf.h
# echo "#define __signed__ signed" > $OUT
# cat $BPF_H >> $OUT
# sed 's/:0;/;/g' $BPF_H > $OUT

popd > /dev/null

# ctypesgen -I `dirname $LIBBPF_H` gen/libbpf.h ./bpftool/libbpf/src/libbpf.c -l ./libbpf.so.1 > gen/libbpf.py
ctypesgen -D__signed__=signed $BPF_H -l ./libbpf.so.1 > gen/bpf.py


# -l ./libbpf.so.1 \
ctypesgen \
-l ./libbpf.so.1 \
-D__signed__=signed \
"-D__builtin_constant_p(x)='1'" \
-I /home/m.bieganski/github/libbpf/include/ \
-I /home/m.bieganski/github/libbpf/include/uapi/ \
$LIBBPF_C $LIBBPF_H > gen/libbpf.py

wc -l gen/libbpf.py
./do_ast.py gen/libbpf.py gen/libbpf.py
wc -l gen/libbpf.py