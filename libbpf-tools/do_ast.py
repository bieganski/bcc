#!/usr/bin/env python3

"""
Workaround for missing 'ctypes' functionality: Alignment of particular struct fields.
See https://discuss.python.org/t/add-ability-to-force-alignment-of-ctypes-structure/39109

The script was initially developed for 'libbpf', that for some of it's structs forces alignment by using 'zero-width' bit fields
(see https://stackoverflow.com/a/13802874). One such example is 'struct bpf_object_open_opts' definition inside libbpf.h.
"""

import ast
from inspect import getmembers
from pprint import pformat
from pathlib import Path
import astor

import ctypes # NOTE: don't remove even despite IDE suggestion. as it is needed, as we call 'eval'.
ctypes.__uint16_t = ctypes.c_ushort
ctypes.__uint32_t = ctypes.c_uint
ctypes.__uint64_t = ctypes.c_ulong
ctypes.__off_t = ctypes.c_long
ctypes.__off64_t = ctypes.c_long
ctypes.__pid_t = ctypes.c_int
ctypes.uint16_t = ctypes.__uint16_t
ctypes.uint32_t = ctypes.__uint32_t
ctypes.uint64_t = ctypes.__uint64_t
ctypes.__u8 = ctypes.c_ubyte
ctypes.__s16 = ctypes.c_short
ctypes.__u16 = ctypes.c_ushort
ctypes.__s32 = ctypes.c_int
ctypes.__u32 = ctypes.c_uint
ctypes.__s64 = ctypes.c_longlong
ctypes.__u64 = ctypes.c_ulonglong
ctypes.enum_bpf_tc_attach_point = ctypes.c_int

x = lambda a: pformat(getmembers(a))
faulty_nodes = []

class Test(ast.NodeVisitor):
    """
    Collects "faulty" assignments.
    "faulty assignment" is defined as follows:
        * assigns to <whatever>._fields_
        * assigns a list of tuples, let's call it 'lst', and following holds: any([x[2] == 0 for x in lst])
    """
    def visit_Assign(self, node):
        # assumption: format compatible with 'ctypesgen' output.
        global faulty_nodes

        target = node.targets[0]
        attr_name_to_be_assigned = getattr(target, "attr", None)
        if attr_name_to_be_assigned != "_fields_":
            return
        
        assert isinstance(node.value, ast.List)

        for tup in node.value.elts:
            if not isinstance(tup, ast.Tuple):
                raise ValueError("Not a tuple!")
            if len(tup.elts) != 3:
                continue
            if not isinstance(tup.elts[2], ast.Constant):
                continue
            if tup.elts[2].value == 0:
                faulty_nodes.append(node)
                return
            

class CtypesStruct_FaultyNodesCollector(ast.NodeTransformer):
    """
    Collects "faulty" assignments.
    "faulty assignment" is defined as follows:
        * assigns to <whatever>._fields_
        * assigns a list of tuples, let's call it 'lst', and following holds: any([x[2] == 0 for x in lst])
    """
    def visit_Assign(self, node):
        # assumption: format compatible with 'ctypesgen' output.
        global faulty_nodes

        if not node in faulty_nodes:
            return node
        
        target = node.targets[0]

        attr_name_to_be_assigned = getattr(target, "attr", None)

        if attr_name_to_be_assigned != "_fields_":
            return
        
        faulty_indices = []
        current_offset = 0
        for i, tup in enumerate(node.value.elts):
            if not isinstance(tup, ast.Tuple):
                raise ValueError("Not a tuple!")
            
            if len(tup.elts) != 3:
                cur: ast.AST = tup.elts[1]
                
                if isinstance(cur, ast.BinOp):
                    
                    assert isinstance(cur.left, ast.Name)
                    assert isinstance(cur.right, ast.Call)
                    assert "int" == cur.right.func.id
                    
                    try:
                        multiplier = cur.right.args[0].value
                    except:
                        raise ValueError(astor.to_source(cur))
                    name = cur.left.id
                    value = eval(f"ctypes.sizeof(ctypes.{name})")
                else:
                    multiplier = 1
                    
                    if isinstance(cur, ast.Call):
                        value = ctypes.sizeof(ctypes.c_char_p)
                    else:
                        name = getattr(cur, "attr", None) or cur.id
                        if name == "String":
                            value = ctypes.sizeof(ctypes.c_char_p)
                        else:
                            value = eval(f"ctypes.sizeof(ctypes.{name})")
                current_slot_size = value - (current_offset % value)
                padding = 0 if (current_slot_size == value) else current_slot_size
                current_offset += padding + value
                # print(f"FIELD {astor.to_source(tup)} increased by {padding + value}")
                continue

            if not isinstance(tup.elts[2], ast.Constant):
                raise ValueError("Unexpected type of tup.elts[2]")
            if tup.elts[2].value != 0:
                continue
            # print(f"faulty node found: {astor.to_source(tup)}")
            assert len(tup.elts) == 3 # make sure we are not missing some data
            faulty_indices.append((i, current_offset, tup.elts[1], tup))

        for i, current_offset, ctypes_type, _ in faulty_indices:

            ctypes_alignment_name = getattr(ctypes_type, "attr", None) or getattr(ctypes_type, "id", None) or ctypes_type.name.id
            requested_alignment = eval(f"ctypes.sizeof(ctypes.{ctypes_alignment_name })")
            num_padding_bytes = requested_alignment - (current_offset % requested_alignment)
            # print(f"inserting padding of {num_padding_bytes} bytes")
            
            for j in range(num_padding_bytes):
                padder = ast.parse('("test", ctypes.c_char)').body[0].value
                assert isinstance(padder, ast.Tuple)
                padder.elts[0] = ast.Constant(value=f"padding_mock{i}_{j}")
                node.value.elts.insert(i, padder)
            
        for _, _, _, faulty in faulty_indices:
            # print("poping ", astor.to_source(faulty))
            node.value.elts.pop(node.value.elts.index(faulty))

        return node

if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    input, output = args.input, args.output

    source_code = input.read_text()
    tree = ast.parse(source_code)
    
    # initial step
    Test().visit(tree)
    # raise ValueError(faulty_nodes)

    node_transformer = CtypesStruct_FaultyNodesCollector()
    new_tree = node_transformer.visit(tree)
    new_source = astor.to_source(new_tree)
    output.write_text(new_source)
