// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "uprobe.skel.h"

#include <sys/syscall.h>      /* Definition of SYS_* constants */
#include <unistd.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

// Duplicate from libbpf:skel_internal.h.
#ifndef offsetofend
#define offsetofend(TYPE, MEMBER) \
	(offsetof(TYPE, MEMBER)	+ sizeof((((TYPE *)0)->MEMBER)))
#endif

int skel_map_update_elem(int fd, const void *key, const void *value, uint64_t flags) {
	/*
	Duplicate of (static) skel_map_update_elem from libbpf:skel_internal.h.
	*/
	const size_t attr_sz = offsetofend(union bpf_attr, flags);
	union bpf_attr attr;

	memset(&attr, 0, attr_sz);
	attr.map_fd = fd;
	attr.key = (long) key;
	attr.value = (long) value;
	attr.flags = flags;
	return syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, &attr, attr_sz);
}

void patch_bpf_map(struct bpf_object* obj, const char* section_name, void* new_value) {
	int map_fd = bpf_object__find_map_fd_by_name(obj, section_name);
	if (map_fd <= 0) {
		printf("%s lookup failed\n", section_name);
		exit(1);
	}

	int key = 0; // we update maps of 'num_elems==1'. key is always 0.
	long syscall_err;
	
	syscall_err = skel_map_update_elem(map_fd, &key, new_value, BPF_ANY);
	if (syscall_err < 0) {
		printf("BPF_MAP_UPDATE_ELEM failed\n");
		exit(1);
	}
}


static inline struct uprobe_bpf *
uprobe_bpf__open_and_load_WITH_VMLINUX(char* vmlinux_path)
{
	struct uprobe_bpf *obj;
	int err;
	struct bpf_object_open_opts *opts = NULL;

	if (vmlinux_path) {
		opts = calloc(sizeof(struct bpf_object_open_opts), 1);
		opts->btf_custom_path = vmlinux_path;
		opts->sz = sizeof(struct bpf_object_open_opts);
	}
	obj = uprobe_bpf__open_opts(opts);
	if (!obj)
		return NULL;
	err = uprobe_bpf__load(obj);
	if (err) {
		uprobe_bpf__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

int main(int argc, char **argv)
{
	if((argc != 3) && (argc != 4)) {
        printf("usage: %s <path to ELF> <symbol name or hex offset> <optional vmlinux path>\n", argv[0]);
        return 1;
    }

	char* symbol_name = argv[2];
	char* elf_path = realpath(argv[1], NULL);
	if (elf_path == NULL) {
		perror("elf_path realpath");
		exit(1);
	}

	char* vmlinux_path = (argc == 4) ? argv[3] : NULL;

	struct uprobe_bpf *skel;
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = uprobe_bpf__open_and_load_WITH_VMLINUX(vmlinux_path);
	
	if (!skel) {
		perror("Failed to open and load BPF skeleton");
		goto cleanup;
	}
	
	errno = 0;
	char* bad = NULL;
	int len = strlen(symbol_name);
	size_t breakpoint_offset;
	
	if (len < 2 || (symbol_name[0] != '0') || (symbol_name[1] != 'x')) {
		printf("treating %s as a symbol, not offset.\n", symbol_name);
		uprobe_opts.func_name = symbol_name;
		breakpoint_offset = 0;
	} else {
		printf("treating %s as an offset, not a symbol.\n", symbol_name);
		breakpoint_offset = strtol(symbol_name, &bad, 16);
	}

	uprobe_opts.retprobe = false;
	int all_pid = -1, self_pid = 0;
	int arg_pid = all_pid;

	// NOTE: map names are inherited from BPF ELF file.
	patch_bpf_map(skel->obj, ".data.symbol_name", symbol_name);
	patch_bpf_map(skel->obj, ".data.library_path", elf_path);
	
	skel->links.uprobe_funcname = bpf_program__attach_uprobe_opts(
		skel->progs.uprobe_funcname,
		arg_pid,
		elf_path,
		breakpoint_offset,
		&uprobe_opts
	);
	if (!skel->links.uprobe_funcname) {
		perror("Failed to attach uprobe");
		goto cleanup;
	}


	uprobe_opts.retprobe = true;
	skel->links.ret_uprobe_funcname = bpf_program__attach_uprobe_opts(
		skel->progs.ret_uprobe_funcname,
		arg_pid,
		elf_path,
		breakpoint_offset,
		&uprobe_opts
	);
	if (!skel->links.ret_uprobe_funcname) {
		perror("Failed to attach uprobe");
		goto cleanup;
	}

	printf("\nSuccessfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
              "to see output of the BPF programs.\n");

	while(1) {
		sleep(1);
	}

cleanup:
	uprobe_bpf__destroy(skel);
	free(elf_path);
	return -1;
}
