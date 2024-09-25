#!/usr/bin/env python3

from inspect import getmembers
from pprint import pformat
from pathlib import Path
import sys
import ctypes
from typing import Type, Optional
import subprocess
import time
import platform
from enum import Enum

import gen.libbpf as libbpf
import gen.bpf as bpf

libc = ctypes.CDLL(None)
syscall = libc.syscall

def die(msg: str = "", exit_code=1, msg_file=sys.stderr):
    if msg:
        print(msg, file=msg_file)
    exit(exit_code)

x = lambda a : pformat(getmembers(a))

def run_shell(cmd: str) -> tuple[str, str]:
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, universal_newlines=True, executable="/bin/bash")
    stdout, stderr = process.communicate()
    if (ecode := process.returncode):
        raise ValueError(f"Command <{cmd}> exited with {ecode}")
    return stdout, stderr

def test_struct_packing():
    libbpf_path = "./libbpf.so.1" # XXX
    for k, v in libbpf.__dict__.items():
        if k.startswith("struct_") and (("bpf" in k) or ("btf" in k) or ("elf_state" in k)):
            # Calculate ctypes struct size.
            instance = v()
            ctypes_size = ctypes.sizeof(instance)

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
                print(f"BAD: Symbol {name_demangled}: Real size is {real_size}, ctypes one {ctypes_size}")

            print(f"Symbol {name_demangled} OK, size {real_size}")



class CPU_Arch(Enum):
    x86_64 = "x86_64"
    riscv64 = "riscv64"
    unknown = "unknown"

def system_get_cpu_arch() -> CPU_Arch:
    machine = platform.machine()
    return CPU_Arch(machine) # TODO: handle 'unknown'

bpf_syscall_nr = {
    CPU_Arch.x86_64: 321,
    CPU_Arch.riscv64: 280,
}

def alloc_writable_buf(type: Type[ctypes.Structure]) -> "ctypes._Pointer[ctypes.Structure]":
    size = ctypes.sizeof(type)
    assert size
    ptr = ctypes.create_string_buffer(init=0, size=size)
    return ctypes.cast(ptr, ctypes.POINTER(type))


def skel_map_update_elem(fd: int, key: ctypes.c_void_p, value: ctypes.c_void_p, flags: int):

    print(f"C")
    time.sleep(1)
    
    attr_ptr = alloc_writable_buf(bpf.union_bpf_attr)
    attr_ptr.contents.map_fd = fd
    attr_ptr.contents.key = ctypes.cast(key, ctypes.c_long)
    attr_ptr.contents.value = ctypes.cast(value, ctypes.c_long)
    attr_ptr.contents.flags = flags

    print(f"D")
    time.sleep(1)
    
    
    sys_bpf = bpf_syscall_nr(system_get_cpu_arch())
    
    return syscall(sys_bpf, bpf.BPF_MAP_UPDATE_ELEM, attr_ptr, ctypes.sizeof(bpf.union_bpf_attr))


def patch_bpf_map(
        obj_ptr: "ctypes._Pointer[libbpf.struct_bpf_object]",
        section_name: str,
        new_value: ctypes._Pointer,
        ):
    
    print(f"A {obj_ptr}")
    time.sleep(1)

    
    map_fd : int = libbpf.bpf_object__find_map_fd_by_name(obj_ptr, libbpf.String(bytes(section_name, "ascii")))
    if map_fd <= 0:
        raise ValueError(f"patch_bpf_map: lookup failed for {section_name}")
    
    print(f"B")
    time.sleep(1)

    
    syscall_err : int = skel_map_update_elem(
        fd=map_fd,
        key=ctypes.byref(ctypes.c_int(0)),
        value=new_value,
        flags=bpf.BPF_ANY
    )

    if syscall_err < 0:
        raise ValueError(f"patch_bpf_map: BPF_MAP_UPDATE_ELEM syscall failed")
    

def bpf__create_skeleton() -> "ctypes._Pointer[libbpf.bpf_object_skeleton]":

    # sizeof_obj = ctypes.sizeof(libbpf.bpf_object) # FIXME: assert sizeof_obj >= real_sizeof_obj (from DWARF)

    s_ptr = alloc_writable_buf(libbpf.bpf_object_skeleton)
    o_ptr = alloc_writable_buf(libbpf.bpf_object)
    
    s = s_ptr.contents

    s.sz = ctypes.sizeof(libbpf.bpf_object_skeleton)
    s.name = libbpf.String(b"uprobe_bpf")
    s.obj = ctypes.cast(o_ptr, ctypes.POINTER(o_ptr.__class__))
    

    ################    MAPS
    s.map_cnt = 1
    s.map_skel_sz = ctypes.sizeof(libbpf.bpf_map_skeleton)
    s.maps = alloc_writable_buf(libbpf.bpf_map_skeleton)

    m = s.maps.contents
    m.name = libbpf.String(b"uprobe_b.rodata")
    # TODO - m.mmaped not set, as it looked strange to me.
    null_ptr = alloc_writable_buf(ctypes.POINTER(libbpf.struct_bpf_map))
    m.map = null_ptr # TODO: later check if it's non-null (should be set by libbpf)

    ################    PROGS
    s.prog_cnt = 1
    s.prog_skel_sz = ctypes.sizeof(libbpf.bpf_prog_skeleton)
    s.progs = alloc_writable_buf(libbpf.bpf_prog_skeleton)

    p = s.progs.contents
    p.name = libbpf.String(b"uprobe_funcname")
    null_ptr = alloc_writable_buf(ctypes.POINTER(libbpf.bpf_program))
    p.prog = null_ptr 

    bpf_elf = Path("./.output/uprobe.bpf.o")
    assert bpf_elf.is_file()
    elf_bytes = bpf_elf.read_bytes()
    elf_size = len(elf_bytes)
    elf_bytes_wrapped = ctypes.cast(ctypes.create_string_buffer(init=elf_bytes, size=elf_size), ctypes.c_void_p)

    s.data_sz = elf_size
    s.data = elf_bytes_wrapped

    return s_ptr


def main(lib: Path, symbol: str, btf: Optional[Path]):
    if btf:
        if not btf.exists():
            raise ValueError(f"Custom BTF path does not exist! {btf}")
        open_opts = libbpf.bpf_object_open_opts(sz=ctypes.sizeof(libbpf.struct_bpf_object_open_opts), btf_custom_path=libbpf.String(bytes(btf, "ascii")))
        open_opts_ptr = ctypes.byref(open_opts)
    else:
        open_opts_ptr = None

    # equivalent of auto-generated ".skel.h" file.
    s_ptr = bpf__create_skeleton()

    err = libbpf.bpf_object__open_skeleton(s_ptr, open_opts_ptr)
    if err != 0:
        die("libbpf.bpf_object__open_skeleton failed")

    err = libbpf.bpf_object__load_skeleton(s_ptr)
    if err != 0:
        die("libbpf.bpf_object__load_skeleton failed")
    
    obj_ptr = s_ptr.contents.obj.contents
    
    for section_name, value in zip([".data.symbol_name", ".data.library_path"], [symbol, str(lib)]):
        patch_bpf_map(
            obj_ptr=obj_ptr,
            section_name=section_name,
            new_value=value, # TODO libbpf.String(bytes(value, "ascii"))
        )

    uprobe_opts =libbpf.struct_bpf_uprobe_opts(
        sz=ctypes.sizeof(libbpf.struct_bpf_uprobe_opts),
        retprobe=False,
        func_name=libbpf.String(bytes(symbol, "ascii"))
    )

    programs_ptr = obj_ptr.contents.programs

    pid_t = ctypes.c_int
    pid_all, pid_self = pid_t(-1), pid_t(0)

    bpf_link = libbpf.bpf_program__attach_uprobe_opts(
        programs_ptr,
        pid_all,                                               # pid
        libbpf.String(bytes(str(lib), "ascii")),               # binary_path
        0,                                                     # func_offset (will be auto-determined anyway)
        ctypes.byref(uprobe_opts),                             # opts
    )

    if bpf_link is None:
        raise ValueError("bpf_program__attach_uprobe_opts returned NULL!")

    print("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.")
    time.sleep(99999)

    raise ValueError("OK")

if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser(usage="XXX")
    parser.add_argument("-l", "--lib", type=Path, required=True, help="path to the library to set userspace breakpoint at.")
    parser.add_argument("-s", "--symbol", type=str, required=True, help="symbol (function) name to set breakpoint at (e.g. 'malloc').")
    parser.add_argument("-b", "--btf", type=Path, help="custom BTF path. if not specified, the ")
    main(**vars(parser.parse_args()))
