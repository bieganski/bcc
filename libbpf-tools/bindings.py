#!/usr/bin/env python3

from ctypes import *

import gen.bpf as bpf
import gen.libbpf as libbpf

from inspect import getmembers
from pprint import pformat

x = lambda a : pformat(getmembers(a))

elf_path = "./.output/uprobe.bpf.o"

bpf_obj = libbpf.bpf_object__open(elf_path)

if bpf_obj is None:
    raise ValueError("'bpf_object__open' failed")

c_char_p = POINTER(c_char)

xx =libbpf.struct_bpf_uprobe_opts(func_name=libbpf.String(b"a"))
raise ValueError(x(xx))

ret = libbpf.bpf_object__load(bpf_obj)
if ret != 0:
    pass # TODO

print(ret)
import time
time.sleep(10000)

res = libbpf.libbpf_probe_bpf_helper(bpf.BPF_PROG_TYPE_KPROBE, bpf.BPF_FUNC_map_lookup_elem, None)
raise ValueError(res)

# skel = libbpf.bpf_object_skeleton()

# libbpf.bpf_object__load_skeleton(skel)