#!/usr/bin/env python3

from pathlib import Path
import sys
import ctypes
from typing import Type, Optional
import subprocess
import platform
from enum import Enum
import signal
import logging

import gen.libbpf as libbpf
import gen.bpf as bpf

from elfparse import find_section_or_raise
from chatgpt_byte_range_swap import op_write_bytes, WriteContext

logging.basicConfig(level=logging.INFO)

libc = ctypes.CDLL(None)
syscall = libc.syscall

def die(msg: str = "", exit_code=1, msg_file=sys.stderr):
    if msg:
        print(msg, file=msg_file)
    exit(exit_code)

def run_shell(cmd: str) -> tuple[str, str]:
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, universal_newlines=True, executable="/bin/bash")
    stdout, stderr = process.communicate()
    if (ecode := process.returncode):
        raise ValueError(f"Command <{cmd}> exited with {ecode}")
    return stdout, stderr

def test_struct_packing():
    """
    TODO: currently not used, but is very useful for testing ctypesgen.

    sizeof ()
    {
        if ! [[ $# -eq 2 ]]; then
            echo 'usage:  sizeof <elf> <struct name>';
            return;
        fi;
        gdb -q -ex "file $1" -ex "printf \"%d\n\", sizeof(struct $2)" -ex quit | grep --color=auto -v Reading
    }

    """
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

def system_get_cpu_arch() -> CPU_Arch:
    machine = platform.machine()
    return CPU_Arch(machine)

bpf_syscall_nr = {
    CPU_Arch.x86_64: 321,
    CPU_Arch.riscv64: 280,
}

pid_t = ctypes.c_int

def alloc_writable_buf(type: Type[ctypes.Structure]) -> "ctypes._Pointer[ctypes.Structure]":
    size = ctypes.sizeof(type)
    assert size
    ptr = ctypes.create_string_buffer(init=bytes(size), size=size)
    return ctypes.cast(ptr, ctypes.POINTER(type))


def skel_map_update_elem(fd: int, key: int, value: bytes, flags: int):

    attr_ptr = alloc_writable_buf(bpf.union_bpf_attr)

    def bpf_attr_find_map_manip_ctype() -> tuple[str, type]:
        for (name, type), (next_name, _) in zip(bpf.union_bpf_attr._fields_, bpf.union_bpf_attr._fields_[1:]):
            if next_name == "batch":
                return (name, type)
        else:
            raise ValueError("suitable ctype needed for bpf_attr not found")

    name, ctype = bpf_attr_find_map_manip_ctype()

    def offsetofend(instance: ctypes.Structure, field: str):
        return getattr(type(instance), field).offset + ctypes.sizeof(dict(instance._fields_)[field])

    union_variant = getattr(attr_ptr.contents, name)
    
    key_storage = ctypes.c_int(key)
    key_addr : int = ctypes.addressof(key_storage)
    
    union_variant.map_fd = fd
    union_variant.key = key_addr
    union_variant.flags = flags
    # NOTE: union_variant.value is set in next step, as it's nested into another anon. union.

    subname_matches = [(x, y) for (x, y) in ctype._fields_ if "unnamed_anon" in  x]
    assert len(subname_matches) == 1
    subname, _ = subname_matches[0]
    union_subvariant = getattr(union_variant, subname)
    
    value_ptr = ctypes.create_string_buffer(init=value, size=len(value))
    union_subvariant.value = ctypes.addressof(value_ptr)

    sys_bpf = bpf_syscall_nr[system_get_cpu_arch()]

    return syscall(sys_bpf, bpf.BPF_MAP_UPDATE_ELEM, attr_ptr, offsetofend(instance=union_variant, field="flags"))


def patch_bpf_map(
        obj_ptr: "ctypes._Pointer[libbpf.struct_bpf_object]",
        section_name: str,
        new_value: bytes,
        ):
    
    assert isinstance(section_name, str) and isinstance(new_value, bytes)
    
    map_fd : int = libbpf.bpf_object__find_map_fd_by_name(obj_ptr, libbpf.String(bytes(section_name, "ascii")))
    if map_fd <= 0:
        raise ValueError(f"patch_bpf_map: lookup failed for {section_name}")
    
    syscall_err : int = skel_map_update_elem(
        fd=map_fd,
        key=0,
        value=new_value,
        flags=bpf.BPF_ANY
    )

    if syscall_err < 0:
        raise ValueError(f"patch_bpf_map: BPF_MAP_UPDATE_ELEM syscall failed")
    

def bpf__create_skeleton(bpf_elf_bytes: bytes) -> "ctypes._Pointer[libbpf.bpf_object_skeleton]":

    assert isinstance(bpf_elf_bytes, bytes)

    # sizeof_obj = ctypes.sizeof(libbpf.bpf_object) # FIXME: assert sizeof_obj >= real_sizeof_obj (from DWARF)

    s_ptr = alloc_writable_buf(libbpf.bpf_object_skeleton)
    o_ptr = alloc_writable_buf(libbpf.bpf_object)
    
    s = s_ptr.contents

    s.sz = ctypes.sizeof(libbpf.bpf_object_skeleton)
    s.name = libbpf.String(b"uprobe_bpf")
    s.obj = ctypes.cast(o_ptr, ctypes.POINTER(o_ptr.__class__))
    

    ################    MAPS
    s.map_cnt = 0 # NOTE: set by libbpf later
    s.map_skel_sz = ctypes.sizeof(libbpf.bpf_map_skeleton)
    s.maps = alloc_writable_buf(libbpf.bpf_map_skeleton)

    ################    PROGS
    s.prog_cnt = 0 # NOTE: set by libbpf later
    s.prog_skel_sz = ctypes.sizeof(libbpf.bpf_prog_skeleton)
    s.progs = alloc_writable_buf(libbpf.bpf_prog_skeleton)

    bpf_elf_size = len(bpf_elf_bytes)
    
    elf_bytes_wrapped = ctypes.cast(ctypes.create_string_buffer(init=bpf_elf_bytes, size=bpf_elf_size), ctypes.c_void_p)

    s.data_sz = bpf_elf_size
    s.data = elf_bytes_wrapped

    return s_ptr

class struct_pt_regs_riscv64(ctypes.Structure):
    _fields_ = [
        ('epc', ctypes.c_ulong),
        ('ra', ctypes.c_ulong),
        ('sp', ctypes.c_ulong),
        ('gp', ctypes.c_ulong),
        ('tp', ctypes.c_ulong),
        ('t0', ctypes.c_ulong),
        ('t1', ctypes.c_ulong),
        ('t2', ctypes.c_ulong),
        ('s0', ctypes.c_ulong),
        ('s1', ctypes.c_ulong),
        ('a0', ctypes.c_ulong),
        ('a1', ctypes.c_ulong),
        ('a2', ctypes.c_ulong),
        ('a3', ctypes.c_ulong),
        ('a4', ctypes.c_ulong),
        ('a5', ctypes.c_ulong),
        ('a6', ctypes.c_ulong),
        ('a7', ctypes.c_ulong),
        ('s2', ctypes.c_ulong),
        ('s3', ctypes.c_ulong),
        ('s4', ctypes.c_ulong),
        ('s5', ctypes.c_ulong),
        ('s6', ctypes.c_ulong),
        ('s7', ctypes.c_ulong),
        ('s8', ctypes.c_ulong),
        ('s9', ctypes.c_ulong),
        ('s10', ctypes.c_ulong),
        ('s11', ctypes.c_ulong),
        ('t3', ctypes.c_ulong),
        ('t4', ctypes.c_ulong),
        ('t5', ctypes.c_ulong),
        ('t6', ctypes.c_ulong),
        ('status', ctypes.c_ulong),
        ('badaddr', ctypes.c_ulong),
        ('cause', ctypes.c_ulong),
        ('orig_a0', ctypes.c_ulong),
    ]

class struct_pt_regs_x86_64(ctypes.Structure):
    _fields_ = [
        ('r15', ctypes.c_ulong),
        ('r14', ctypes.c_ulong),
        ('r13', ctypes.c_ulong),
        ('r12', ctypes.c_ulong),
        ('bp', ctypes.c_ulong),
        ('bx', ctypes.c_ulong),
        ('r11', ctypes.c_ulong),
        ('r10', ctypes.c_ulong),
        ('r9', ctypes.c_ulong),
        ('r8', ctypes.c_ulong),
        ('ax', ctypes.c_ulong),
        ('cx', ctypes.c_ulong),
        ('dx', ctypes.c_ulong),
        ('si', ctypes.c_ulong),
        ('di', ctypes.c_ulong),
        ('orig_ax', ctypes.c_ulong),
        ('ip', ctypes.c_ulong),
        ('cs', ctypes.c_ulong),
        ('flags', ctypes.c_ulong),
        ('sp', ctypes.c_ulong),
        ('ss', ctypes.c_ulong),
    ]

class union_pt_regs(ctypes.Union):
    _fields_ = [
        ("x86_64", struct_pt_regs_x86_64),
        ("riscv64", struct_pt_regs_riscv64),
    ]

# Define the struct event in Python
class Event(ctypes.Structure):
    _fields_ = [
        ("library_path", ctypes.c_char * 128),
        ("symbol_name", ctypes.c_char * 64),
        ("pid", ctypes.c_int32),
        ("tid", ctypes.c_int32),

        ("timestamp",   ctypes.c_uint64),
        ("is_ret",      ctypes.c_int32),

        ("pt_regs_union", union_pt_regs)
    ]


# key: (library, symbol, pid, tid)
last_entry_event_dict = dict()

def fmt_ns(timedelta_ns: int) -> str:
    return f"{(timedelta_ns / 1_000_000_000):.7f} seconds"

def fmt_regs(reg_names: list[str], pt_regs: ctypes.Structure) -> str:
    res = ""
    for i, name in enumerate(reg_names):
        res += f"{name}={hex(getattr(pt_regs, name))}"
        if not (last := i == len(reg_names) - 1):
            res += ", "
    return res

def get_regs_of_interest(arch: CPU_Arch, is_ret: bool) -> list[str]:
    if arch == CPU_Arch.x86_64:
        return ["ax"] if is_ret else ["di", "si", "dx", "cx", "r8", "r9", "r10"]
    elif arch == CPU_Arch.riscv64:
        return ["a0"] if is_ret else [f"a{i}" for i in range(6)]
    else:
        assert False


@ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(None), ctypes.c_size_t)
def handle_event(ctx, data, data_sz):
    """
    IMPORTANT NOTE:

    waiting sufficiently long time, the content of 'data' will change, as kernel will keep reusing same userspace pointer for new incoming events.

    in order to (only) minimize the risk of data incoherency, first thing that we do in the handler is to memcpy @data content.
    """

    assert data_sz == ctypes.sizeof(Event)

    event_ptr = ctypes.cast(data, ctypes.POINTER(Event))
    event = Event()
    ctypes.memmove(ctypes.byref(event), ctypes.byref(event_ptr.contents), data_sz)
    # alternative thing, that causes data incoherency mentioned above: "event : Event = event_ptr.contents"
    
    lib_basename = event.library_path.decode("ascii").split("/")[-1]
    symbol_name = event.symbol_name.decode("ascii")
    hash = (lib_basename, symbol_name, event.pid, event.tid)

    arch = system_get_cpu_arch()

    pt_regs = getattr(event.pt_regs_union, system_get_cpu_arch().value)

    msg_prefix = f"[{event.pid},{event.tid}][{lib_basename}:{symbol_name}]"

    if event.is_ret:
        
        if not (prev_entry_event := last_entry_event_dict.get(hash)):
            assert False # uretprobe is set on uprobe hit from the same process, see 'handler_chain' in kernel/events/uprobes.c

        exec_time_ns = event.timestamp - prev_entry_event.timestamp
        assert exec_time_ns > 0

        print(f"{msg_prefix} RET ({fmt_regs(reg_names=get_regs_of_interest(arch=arch, is_ret=True), pt_regs=pt_regs)}) exec_time_ns: {fmt_ns(exec_time_ns)}")
    else:

        # fetch previous event and update with the new one
        prev_entry_event = last_entry_event_dict.get(hash)
        last_entry_event_dict[hash] = event

        first_hit_of_hash = (not prev_entry_event)

        regs_str = fmt_regs(reg_names=get_regs_of_interest(arch=arch, is_ret=False), pt_regs=pt_regs)

        if not first_hit_of_hash:
            reentry_delta_ns = event.timestamp - prev_entry_event.timestamp
            msg_infix = f"REENTRY after {fmt_ns(reentry_delta_ns)}"
        else:
            msg_infix = f"FIRST ENTRY"

        print(f"{msg_prefix} {msg_infix} {regs_str}")
    return 0

def preprocess_bpf_elf(elf_bytes: bytes) -> bytes:
    native_arch = system_get_cpu_arch()

    for arch in CPU_Arch:
        arch_section = find_section_or_raise(elf_content=elf_bytes, sec_name=f".data.arch_is_{arch.value}")
        assert arch_section.content_length == 4

        val = bytes(ctypes.c_uint32(1 if arch == native_arch else 0))
        
        op = WriteContext(offset=arch_section.content_file_offset, bytes_to_write=val)
        elf_bytes = op_write_bytes(context=op, input_data=elf_bytes)

    return elf_bytes

def main(lib: Path, symbol_or_offset: str, btf: Optional[Path], pid: str, no_retprobe: bool, bpf_elf: Path):
    if btf:
        if not btf.exists():
            raise ValueError(f"Custom BTF path does not exist! {btf}")
        open_opts = libbpf.bpf_object_open_opts(sz=ctypes.sizeof(libbpf.struct_bpf_object_open_opts), btf_custom_path=libbpf.String(bytes(str(btf), "ascii")))
        open_opts_ptr = ctypes.byref(open_opts)
    else:
        open_opts_ptr = None
    
    # adjust to native CPU arch
    elf_bytes = preprocess_bpf_elf(bpf_elf.read_bytes())

    # equivalent of auto-generated ".skel.h" file.
    s_ptr = bpf__create_skeleton(bpf_elf_bytes=elf_bytes)

    err = libbpf.bpf_object__open_skeleton(s_ptr, open_opts_ptr)
    if err != 0:
        die("libbpf.bpf_object__open_skeleton failed")

    err = libbpf.bpf_object__load_skeleton(s_ptr)
    if err != 0:
        die("libbpf.bpf_object__load_skeleton failed")
    
    obj_ptr = s_ptr.contents.obj.contents
    
    for section_name, value in zip([".data.symbol_name", ".data.library_path"], [symbol_or_offset, str(lib)]):
        patch_bpf_map(
            obj_ptr=obj_ptr,
            section_name=section_name,
            new_value=bytes(value, "ascii") + b'\x00',
        )

    def ctypesgen_String_nullptr_workaround() -> libbpf.String:
        """
        TODO: 'ctypesgen' tries to be smart and defines 'class String', that is not convenient for us at all.
        Otherwise we could just use 'ctypes.POINTER()', and ctypes would convert it to nullptr automatically.
        """
        res = libbpf.String()
        res.raw = ctypes.POINTER(ctypes.c_char)()
        return res

    try:
        uprobe_file_offset = int(symbol_or_offset, 16)
        func_name = ctypesgen_String_nullptr_workaround()
    except:
        uprobe_file_offset = 0
        func_name = libbpf.String(bytes(symbol_or_offset, "ascii"))

    uprobe_opts =libbpf.struct_bpf_uprobe_opts(
        sz=ctypes.sizeof(libbpf.struct_bpf_uprobe_opts),
        retprobe=False,
        func_name=func_name,
    )

    if pid == "self":
        pid_int = pid_t(0)
    elif pid == "all":
        pid_int = pid_t(-1)
    else:
        pid_int = pid_t(int(pid))

    programs_ptr = obj_ptr.contents.programs
    assert (num_progs := obj_ptr.contents.nr_programs) == 2
    
    # NOTE: be careful here, as 'nr_programs' is also incremented for non-inlined static functions.
    # https://mailweb.openeuler.org/hyperkitty/list/kernel@openeuler.org/message/I7OJDEIGUDF42JEBJ5BDAZRNCLYIZCV5/
    for i in range(num_progs):
        if "ret_" in programs_ptr[i].name.data.decode("ascii"):
            uprobe_opts.retprobe = True
            logging.info(f"prog[{i}] is uretprobe")

            if no_retprobe:
                logging.info("skipping uretprobe application (on user request)")
                continue
        else:
            uprobe_opts.retprobe = False
            logging.info(f"prog[{i}] is not uretprobe")
        
        bpf_link = libbpf.bpf_program__attach_uprobe_opts(
            programs_ptr[i],
            pid_int,                                               # pid
            libbpf.String(bytes(str(lib), "ascii")),               # binary_path
            uprobe_file_offset,                                    # func_offset (not necessarily will be used)
            ctypes.byref(uprobe_opts),                             # opts
        )

        if not bpf_link:
            raise ValueError("bpf_program__attach_uprobe_opts returned NULL!")
    
    rb_map_fd : int = libbpf.bpf_object__find_map_fd_by_name(obj_ptr, libbpf.String(b"rb"))
    if rb_map_fd <= 0:
        raise ValueError(f"patch_bpf_map: lookup failed for map 'rb'")
    
    ring_buffer = libbpf.ring_buffer__new(rb_map_fd, handle_event, None, None)

    logging.info("Successfully loaded BPF programs! Start ringbuf polling..")

    while True:
        err = libbpf.ring_buffer__poll(ring_buffer, 100)
        if err < 0:
            print("libbpf.ring_buffer__poll BAD")

if __name__ == "__main__":
    # clean handling of Ctrl-C, as ringbuf polling messes with it.
    def sig_handler(signum, frame):
        exit(1)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    from argparse import ArgumentParser
    parser = ArgumentParser(usage="libbpy python bindings loader")
    parser.add_argument("lib", type=Path, help="path to the library to set userspace breakpoint at.")
    parser.add_argument("symbol_or_offset", help="symbol name or hex file offset to set breakpoint at (e.g. 'malloc' or '0x2068').")
    parser.add_argument("-b", "--btf", type=Path, help="custom BTF path. if not specified, libbpf will seek for 'vmlinux' in default locations (e.g. sysfs)")
    parser.add_argument("-e", "--bpf-elf", type=Path, default=Path("./.output/uprobe.bpf.o"))
    parser.add_argument("-p", "--pid", default="all", help="PID to be traced. Either an int, or 'self', or 'all'. Defaults to 'all'")
    parser.add_argument("-nr", "--no-retprobe", action="store_true")
    main(**vars(parser.parse_args()))
