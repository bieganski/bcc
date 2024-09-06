#!/usr/bin/env python3

# import ctypes
# from ctypes import c_void_p, c_char_p, c_int, c_size_t, c_uint32, c_bool, POINTER

# # Load the shared library (assumes libbpf.so is available in the system path)
# libbpf = ctypes.CDLL('libbpf.so')

# # Define basic types used in the function signatures
# class btf(ctypes.Structure):
#     pass

# class btf_ext(ctypes.Structure):
#     pass

# class btf_type(ctypes.Structure):
#     pass

# # Enums
# class btf_endianness(ctypes.c_int):
#     BTF_LITTLE_ENDIAN = 0
#     BTF_BIG_ENDIAN = 1

# # Function prototypes

# # void btf__free(struct btf *btf);
# libbpf.btf__free.argtypes = [POINTER(btf)]
# libbpf.btf__free.restype = None

# # struct btf *btf__new(const void *data, __u32 size);
# libbpf.btf__new.argtypes = [ctypes.c_void_p, c_uint32]
# libbpf.btf__new.restype = POINTER(btf)

# # struct btf *btf__new_split(const void *data, __u32 size, struct btf *base_btf);
# libbpf.btf__new_split.argtypes = [ctypes.c_void_p, c_uint32, POINTER(btf)]
# libbpf.btf__new_split.restype = POINTER(btf)

# # struct btf *btf__new_empty(void);
# libbpf.btf__new_empty.restype = POINTER(btf)

# # struct btf *btf__new_empty_split(struct btf *base_btf);
# libbpf.btf__new_empty_split.argtypes = [POINTER(btf)]
# libbpf.btf__new_empty_split.restype = POINTER(btf)

# # int btf__distill_base(const struct btf *src_btf, struct btf **new_base_btf, struct btf **new_split_btf);
# libbpf.btf__distill_base.argtypes = [POINTER(btf), POINTER(POINTER(btf)), POINTER(POINTER(btf))]
# libbpf.btf__distill_base.restype = c_int

# # struct btf *btf__parse(const char *path, struct btf_ext **btf_ext);
# libbpf.btf__parse.argtypes = [c_char_p, POINTER(POINTER(btf_ext))]
# libbpf.btf__parse.restype = POINTER(btf)

# # struct btf *btf__load_vmlinux_btf(void);
# libbpf.btf__load_vmlinux_btf.restype = POINTER(btf)

# # Example usage
# if __name__ == '__main__':
#     # Load vmlinux BTF
#     vmlinux_btf = libbpf.btf__load_vmlinux_btf()
#     if not vmlinux_btf:
#         print("Failed to load vmlinux BTF")
#     else:
#         print("Successfully loaded vmlinux BTF")

#     # Free the BTF object
#     libbpf.btf__free(vmlinux_btf)


import gen_bindings
# raise ValueError(dir(gen_bindings))
from gen_bindings import bpf_object__load_skeleton

bpf_object__load_skeleton()