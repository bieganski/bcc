#!/usr/bin/env python3

from ctypes import *

import gen.bpf as bpf
import gen.libbpf as libbpf

from inspect import getmembers
from pprint import pformat

x = lambda a : pformat(getmembers(a))
ad = lambda a : hex(addressof(a))

import subprocess
def run_shell(cmd: str) -> tuple[str, str]:
    
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, universal_newlines=True, executable="/bin/bash")
    stdout, stderr = process.communicate()
    if (ecode := process.returncode):
        raise ValueError(f"Command <{cmd}> exited with {ecode}")
    return stdout, stderr

def test_struct_packing():
    libbpf_path = "./libbpf.so.1" # XXX
    for k, v in libbpf.__dict__.items():
        if k.startswith("struct_") and "bpf" in k:
            # Calculate ctypes struct size.
            instance = v()
            ctypes_size = sizeof(instance)

            # Calculate real struct size.
            name_demangled = k[7:]
            try:
                stdout, _ = run_shell(f"./sizeof.sh {libbpf_path} {name_demangled}")
            except ValueError:
                print(f"Symbol {name_demangled} apparently not present in {libbpf_path}! Skipping..")
                continue
            real_size = int(stdout) # 'real', as comes from compiled library's DWARF.
            
            # Compare struct sizes.
            if ctypes_size != real_size:
                raise ValueError(f"Symbol {name_demangled}: Real size is {real_size}, ctypes one {ctypes_size}")

            print(f"Symbol {name_demangled} OK, size {real_size}")

test_struct_packing()
raise ValueError("K")
open_opts = libbpf.bpf_object_open_opts(btf_custom_path=libbpf.String(b"siema"))
bpf_obj = libbpf.bpf_object__open_file("./.output/uprobe.bpf.o", byref(open_opts))
# raise ValueError("stop")

# elf_path = "./.output/uprobe.bpf.o"
# bpf_obj = libbpf.bpf_object__open(elf_path)


# lol = pointer(cast(bpf_obj, c_void_p))[312]
print("ad", ad(bpf_obj))
raise ValueError(bpf_obj.contents)
ptr = cast(bpf_obj, c_void_p)

raise ValueError(ad(bpf_obj.contents))

if bpf_obj is None:
    raise ValueError("'bpf_object__open' failed")

for name, value, *_ in bpf_obj.contents._fields_:
    if name == "btf_custom_path":
        raise ValueError(value.data, getattr(bpf_obj.contents, name))
    print(name, getattr(bpf_obj.contents, name))

raise ValueError("OK")

uprobe_opts =libbpf.struct_bpf_uprobe_opts(
    sz=sizeof(libbpf.struct_bpf_uprobe_opts),
    ref_ctr_offset=0,
    bpf_cookie=0,
    retprobe=False,
    func_name=libbpf.String(b"malloc")
)

bpf_link = libbpf.bpf_program__attach_uprobe_opts(
    bpf_obj.contents.programs, # bpf_program*                 prog=
    0, # own process                                          pid=
    libbpf.String(b"/lib/x86_64-linux-gnu/libc.so.6"), #      binary_path=
    0, # size_t, will be auto-determined                      func_offset=
    uprobe_opts, #                                            opts=
)
if bpf_link is None:
    raise ValueError("bpf_program__attach_uprobe_opts returned NULL!")

raise ValueError(bpf_link)

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