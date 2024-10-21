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

int all_pid = -1, self_pid = 0;

char *find_library_path(const char *libname) {
	char cmd[128];
	static char path[512];
	FILE *fp;

	// Construct the ldconfig command with grep
	snprintf(cmd, sizeof(cmd), "ldconfig -p | grep %s", libname);

	// Execute the command and read the output
	fp = popen(cmd, "r");
	if (fp == NULL) {
		perror("Failed to run ldconfig");
		return NULL;
	}

	// Read the first line of output which should have the library path
	if (fgets(path, sizeof(path) - 1, fp) != NULL) {
		// Extract the path from the ldconfig output
		char *start = strrchr(path, '>');
		if (start && *(start + 1) == ' ') {
			memmove(path, start + 2, strlen(start + 2) + 1);
			char *end = strchr(path, '\n');
			if (end) {
				*end = '\0';  // Null-terminate the path
			}
			pclose(fp);
			return path;
		}
	}

	pclose(fp);
	return NULL;
}

int main(int argc, char **argv)
{
	if(argc != 2) {
        printf("usage: %s <vmlinux path> (try passing /sys/kernel/btf/vmlinux)\n", argv[0]);
        return 1;
    }

	// char* symbol_name = argv[2];
	// char* elf_path = realpath(argv[1], NULL);
	// if (elf_path == NULL) {
	// 	perror("elf_path realpath");
	// 	exit(1);
	// }

	char* vmlinux_path = argv[1];

	struct uprobe_bpf *skel;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = uprobe_bpf__open_and_load_WITH_VMLINUX(vmlinux_path);
	
	if (!skel) {
		perror("Failed to open and load BPF skeleton");
		goto cleanup;
	}

	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);
	
	// uprobe_opts.func_name = "SSL_read";
	uprobe_opts.func_name = "malloc";
	
	uprobe_opts.func_name = "libbpf_find_kernel_btf";
	
	uprobe_opts.retprobe = false;
	
	// char* openssl_path = find_library_path("libssl.so");


	// char* openssl_path = find_library_path("libssl.so.1.1");
	// char* openssl_path = find_library_path("libc.so.6");
	char* openssl_path = find_library_path("libbpf.so.1");

	
	printf("OpenSSL path: %s\n", openssl_path);

	skel->links.probe_SSL_read = bpf_program__attach_uprobe_opts(
		skel->progs.probe_SSL_read,
		all_pid,
		openssl_path,
		0, // arg_offset, not used
		&uprobe_opts
	);
	if (!skel->links.probe_SSL_read) {
		perror("Failed to attach uprobe");
		goto cleanup;
	}

	// uprobe_opts.retprobe =1 ;


	// skel->links.probe_SSL_read_exit = bpf_program__attach_uprobe_opts(
	// 	skel->progs.probe_SSL_read_exit,
	// 	all_pid,
	// 	openssl_path,
	// 	0, // arg_offset, not used
	// 	&uprobe_opts
	// );
	// if (!skel->links.probe_SSL_read_exit) {
	// 	perror("Failed to attach uprobe");
	// 	goto cleanup;
	// }

	printf("\nSuccessfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
              "to see output of the BPF programs.\n");
	while(1) {
		sleep(1);
	}

cleanup:
	uprobe_bpf__destroy(skel);
	return -1;
}
