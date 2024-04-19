// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "uprobe.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{

	if(argc != 3) {
        printf("usage: %s <path to ELF> <symbol name>\n", argv[0]);
        return 1;
    }

	char* symbol_name = argv[2];
	char* elf_path = realpath(argv[1], NULL);
	if (elf_path == NULL) {
		perror("elf_path realpath");
		exit(1);
	}

	struct uprobe_bpf *skel;
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = uprobe_bpf__open_and_load();
	if (!skel) {
		perror("Failed to open and load BPF skeleton");
		goto cleanup;
	}

	uprobe_opts.func_name = symbol_name;
	uprobe_opts.retprobe = false;
	int all_pid = -1, self_pid = 0;
	
	int arg_pid = all_pid;
	int arg_offset = 0; // TODO not implemented
	skel->links.xdddwrite = bpf_program__attach_uprobe_opts(
		skel->progs.xdddwrite,
		arg_pid,
		elf_path,
		arg_offset,
		&uprobe_opts
	);
	if (!skel->links.xdddwrite) {
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
