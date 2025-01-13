#!/usr/bin/env python3

import argparse
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)

class Op(Enum):
    shift_range_left = "shift_range_left"
    write = "write"
    csv = "csv"
    read = "read"
    verify = "verify"

@dataclass
class ShiftRangeLeftContext:
    r_min_incl: int
    r_max_excl: int
    num: int

    def to_csv(self) -> str:
        return f"shift_range_left,{hex(self.r_min_incl)},{hex(self.r_max_excl)},{hex(self.num)}"

@dataclass
class WriteContext:
    offset: int
    bytes_to_write: bytes

    def to_csv(self) -> str:
        return f"write,{hex(self.offset)},{self.bytes_to_write.hex()}"

@dataclass
class ReadContext:
    offset: int
    size: int

    def to_csv(self) -> str:
        return f"read,{hex(self.offset)},{hex(self.size)}"


@dataclass
class VerifyContext:
    offset: int
    reference: bytes

    def to_csv(self) -> str:
        return f"verify,{hex(self.offset)},{self.reference.hex()}"

def op_shift_range_left(*, input_data: bytes, context: ShiftRangeLeftContext) -> bytes:
    if context.r_min_incl < context.num:
        raise ValueError(f"Invalid NUM value: NUM ({context.num}) is greater than or equal to r_min_incl ({context.r_min_incl}).")
    if context.r_min_incl >= context.r_max_excl:
        raise ValueError(f"Invalid byte range: r_min_incl ({context.r_min_incl}) must be less than r_max_excl ({context.r_max_excl}).")

    data = bytearray(input_data)

    range1 = data[context.r_min_incl - context.num:context.r_min_incl]  # Bytes from (Rmin-NUM) to Rmin
    range2 = data[context.r_min_incl:context.r_max_excl]                # Bytes from Rmin to Rmax

    data[context.r_min_incl - context.num:context.r_max_excl] = range2 + range1
    return data

def op_write_bytes(*, input_data: bytes, context: WriteContext) -> bytes:
    """
    we allow for out-of-bounds write. the gap will be filled with zeros.
    """
    off   = context.offset
    patch = context.bytes_to_write

    if off < 0:
        raise ValueError(f"Invalid offset: offset ({context.offset}) must be non-negative.")

    new_size = max(len(input_data), off + len(patch))

    res = bytearray(new_size)

    res[:len(input_data)] = input_data
    res[off:off + len(patch)] = patch

    return bytes(res)

def op_read_bytes(*, input_data: bytes, context: ReadContext) -> None:
    if context.offset < 0 or context.offset + context.size > len(input_data):
        raise ValueError(f"Invalid read range: offset ({context.offset}) and size ({context.size}) out of bounds.")
    
    read_data = input_data[context.offset:context.offset + context.size]
    print(read_data.hex())
    return input_data

def op_verify_bytes(*, input_data: bytes, context: VerifyContext) -> None:
    if context.offset < 0 or context.offset + len(context.reference) > len(input_data):
        raise ValueError(f"Invalid verify range: offset ({context.offset}) and size ({context.size}) out of bounds.")

    actual_data = input_data[context.offset:context.offset + len(context.reference)]
    if actual_data != context.reference:
        fmt_act = actual_data[:8].hex()
        fmt_ref = context.reference[:8].hex()
        raise ValueError(f"Verification failed at offset {hex(context.offset)}: got {fmt_act} vs expected {fmt_ref}")
    return input_data

def main_shift_range_left(args: argparse.Namespace) -> bytes:
    r_min_incl, r_max_excl = [int(x, 16) for x in args.byte_range.split(',')]
    context = ShiftRangeLeftContext(r_min_incl=r_min_incl, r_max_excl=r_max_excl, num=args.num)
    logging.info(f"executing {context.to_csv()}")
    input_data = Path(args.input_file).read_bytes()
    return op_shift_range_left(
        input_data=input_data,
        context=context
    )

def main_write(args: argparse.Namespace) -> bytes:
    offset = int(args.offset, 16)
    bytes_to_write = bytes.fromhex(args.bytes)
    context = WriteContext(offset=offset, bytes_to_write=bytes_to_write)
    logging.info(f"executing {context.to_csv()}")
    input_data = Path(args.input_file).read_bytes()
    return op_write_bytes(
        input_data=input_data,
        context=context
    )

def main_read(args: argparse.Namespace) -> None:
    offset = int(args.offset, 16)
    size = args.size
    context = ReadContext(offset=offset, size=size)
    logging.info(f"executing {context.to_csv()}")
    input_data = Path(args.input_file).read_bytes()
    op_read_bytes(
        input_data=input_data,
        context=context
    )

def main_verify(args: argparse.Namespace) -> None:
    offset = int(args.offset, 16)
    size = args.size
    reference = bytes.fromhex(args.reference)
    context = VerifyContext(offset=offset, size=size, reference=reference)
    logging.info(f"executing {context.to_csv()}")
    input_data = Path(args.input_file).read_bytes()
    op_verify_bytes(
        input_data=input_data,
        context=context
    )

def main_csv(args: argparse.Namespace) -> bytes:
    data = Path(args.input_file).read_bytes()

    commands_lines = [x.strip() for x in Path(args.csv_file).read_text().splitlines() if x.strip()]

    for line in commands_lines:

        parts = line.split(',')
        op_name = parts[0]

        if op_name == Op.shift_range_left.value:
            r_min_incl, r_max_excl, num = map(lambda x: int(x, 16), parts[1:])
            context = ShiftRangeLeftContext(r_min_incl=r_min_incl, r_max_excl=r_max_excl, num=num)
            data = op_shift_range_left(input_data=data, context=context)

        elif op_name == Op.write.value:
            offset = int(parts[1], 16)
            bytes_to_write = bytes.fromhex(parts[2])
            context = WriteContext(offset=offset, bytes_to_write=bytes_to_write)
            data = op_write_bytes(input_data=data, context=context)

        elif op_name == Op.read.value:
            offset = int(parts[1], 16)
            size = int(parts[2], 16)
            context = ReadContext(offset=offset, size=size)
            op_read_bytes(input_data=data, context=context)

        elif op_name == Op.verify.value:
            offset = int(parts[1], 16)
            reference = bytes.fromhex(parts[2])
            context = VerifyContext(offset=offset, reference=reference)
            op_verify_bytes(input_data=data, context=context)

        else:
            raise ValueError(f"Unknown operation '{op_name}' in CSV file.")

    return data

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Perform operations on byte ranges in a file.")
    subparsers = parser.add_subparsers(title="Operations", dest="operation", required=True)

    # Subparser for SHIFT_RANGE_LEFT
    parser_shift = subparsers.add_parser(Op.shift_range_left.value, help="Shift a byte range left.")
    parser_shift.add_argument("input_file", help="Path to the input file.")
    parser_shift.add_argument("byte_range", help="Byte range in the format 'start,end' (both in hex).")
    parser_shift.add_argument("num", type=int, help="Positive integer value for NUM.")
    parser_shift.add_argument("output_file", help="Path to the output file.")
    parser_shift.set_defaults(func=main_shift_range_left)

    # Subparser for WRITE
    parser_write = subparsers.add_parser(Op.write.value, help="Write bytes to a specific offset.")
    parser_write.add_argument("input_file", help="Path to the input file.")
    parser_write.add_argument("offset", help="Offset in the file to write the bytes (in hex).")
    parser_write.add_argument("bytes", help="Bytes to write, as a hexadecimal string.")
    parser_write.add_argument("output_file", help="Path to the output file.")
    parser_write.set_defaults(func=main_write)

    # Subparser for READ
    parser_read = subparsers.add_parser(Op.read.value, help="Read bytes from a specific offset.")
    parser_read.add_argument("input_file", help="Path to the input file.")
    parser_read.add_argument("offset", help="Offset in the file to read from (in hex).")
    parser_read.add_argument("size", type=int, help="Number of bytes to read.")
    parser_read.set_defaults(func=main_read)

    # Subparser for VERIFY
    parser_verify = subparsers.add_parser(Op.verify.value, help="Verify bytes at a specific offset.")
    parser_verify.add_argument("input_file", help="Path to the input file.")
    parser_verify.add_argument("offset", help="Offset in the file to verify from (in hex).")
    parser_verify.add_argument("size", type=int, help="Number of bytes to verify.")
    parser_verify.add_argument("reference", help="Reference bytes to compare, as a hexadecimal string.")
    parser_verify.set_defaults(func=main_verify)

    # Subparser for CSV
    parser_csv = subparsers.add_parser(Op.csv.value, help="Process multiple operations from a CSV file.")
    parser_csv.add_argument("input_file", help="Path to the input file.")
    parser_csv.add_argument("csv_file", help="Path to the CSV file with operations.")
    parser_csv.add_argument("output_file", help="Path to the output file.")
    parser_csv.set_defaults(func=main_csv)

    # Parse arguments and invoke the corresponding function
    args = parser.parse_args()

    result = args.func(args)
    
    # some ops might not update the data, e.g. read or verify.
    if result is not None:
        Path(args.output_file).write_bytes(result)
