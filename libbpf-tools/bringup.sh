#!/bin/bash

set -eux

path=./.output/bpf/usdt.bpf.h
file -E $path

sed -i 's:linux/errno.h:asm-generic/errno.h:g' $path
