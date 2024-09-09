#!/usr/bin/env python3

import gen.bpf as bpf
import gen.libbpf as libbpf

res = libbpf.libbpf_probe_bpf_helper(bpf.BPF_PROG_TYPE_KPROBE, bpf.BPF_FUNC_map_lookup_elem, None)
raise ValueError(res)

# skel = libbpf.bpf_object_skeleton()

# libbpf.bpf_object__load_skeleton(skel)