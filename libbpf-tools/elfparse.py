#!/usr/bin/env python3

from pathlib import Path
import logging
import ctypes
from io import BytesIO

logging.basicConfig(level=logging.INFO)

from pprint import pformat
from inspect import getmembers
x = lambda _a: pformat(getmembers(_a))


Elf64_Addr = ctypes.c_uint64
Elf64_Off = ctypes.c_uint64
Elf64_Word = ctypes.c_uint32
Elf64_Xword = ctypes.c_uint64
Elf64_Half = ctypes.c_uint16

class Elf64_Ehdr(ctypes.Structure):
    _fields_ = [
        ("e_ident", (ctypes.c_ubyte * 16)),
        ("e_type", Elf64_Half),
        ("e_machine", Elf64_Half),
        ("e_version", Elf64_Word),
        ("e_entry", Elf64_Addr),
        ("e_phoff", Elf64_Off),
        ("e_shoff", Elf64_Off),
        ("e_flags", Elf64_Word),
        ("e_ehsize", Elf64_Half),
        ("e_phentsize", Elf64_Half),
        ("e_phnum", Elf64_Half),
        ("e_shentsize", Elf64_Half),
        ("e_shnum", Elf64_Half),
        ("e_shstrndx", Elf64_Half),
    ]

class Elf64_Shdr(ctypes.Structure):
    _fields_ = [
        ("sh_name", Elf64_Word),
        ("sh_type", Elf64_Word),
        ("sh_flags", Elf64_Xword),
        ("sh_addr", Elf64_Addr),
        ("sh_offset", Elf64_Off),
        ("sh_size", Elf64_Xword),
        ("sh_link", Elf64_Word),
        ("sh_info", Elf64_Word),
        ("sh_addralign", Elf64_Xword),
        ("sh_entsize", Elf64_Xword),
    ]

    @property
    def content_length(self) -> int:
        return self.sh_size

    @property
    def content_file_offset(self) -> int:
        return self.sh_offset
    
    def __repr__(self) -> str:
        return f"section of size {hex(self.content_length)} at file offset {hex(self.content_file_offset)}"


def get_null_terminated_str(data: bytes, first_byte_offset: int) -> str:
    return data[first_byte_offset:].split(b"\0")[0].decode("ascii")

def find_section_or_raise(elf_content: bytes, sec_name: str) -> Elf64_Shdr:
    stream = BytesIO(elf_content)

    if stream.read(4) != bytes([0x7f, ord('E'), ord('L'), ord('F')]):
        raise ValueError("Not an ELF")
    
    stream.seek(0)

    elf_header = Elf64_Ehdr.from_buffer_copy(stream.read(ctypes.sizeof(Elf64_Ehdr)))

    section_header_off = elf_header.e_shoff
    assert section_header_off != 0  # "If the file has no section header table, this member holds zero."

    # first, parse names XXX
    section_name_string_table_idx = elf_header.e_shstrndx

    # "If the file has no section name string table, this member holds the value SHN_UNDEF."
    if section_name_string_table_idx == (SHN_UNDEF := 0):
        assert False

    section_name_header_offset = section_header_off + (section_name_string_table_idx * elf_header.e_shentsize)
    stream.seek(section_name_header_offset)
    sec_header_names = Elf64_Shdr.from_buffer_copy(stream.read(ctypes.sizeof(Elf64_Shdr)))
    
    string_table_raw = elf_content[sec_header_names.sh_offset:][:sec_header_names.sh_size]

    stream.seek(section_header_off)
    for _ in range(elf_header.e_shnum):
        sec_header = Elf64_Shdr.from_buffer_copy(stream.read(ctypes.sizeof(Elf64_Shdr)))
        if sec_header.sh_name != 0:
            cur_sec_name = get_null_terminated_str(data=string_table_raw, first_byte_offset=sec_header.sh_name)
            if sec_name == cur_sec_name:
                return sec_header
    else:
        raise ValueError(f"Could not find section {sec_name} inside ELF")

def main(elf_path: Path):
    
    res = find_section_or_raise(elf_content=elf_path.read_bytes(), sec_name=".data.arch_is_x86_64")
    print(res)

if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser(usage="XXX")
    parser.add_argument("elf_path", type=Path)
    main(**vars(parser.parse_args()))
