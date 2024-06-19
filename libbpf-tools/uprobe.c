// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "uprobe.skel.h"

#include <assert.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct uprobe_bpf *obj = uprobe_bpf__open();
	if (!obj) {
		perror("uprobe_bpf__open");
		exit(1);
	}

	obj->rodata->is_bpf_jiffies64_supported = 0;

	int err = uprobe_bpf__load(obj);
	if (err) {
		uprobe_bpf__destroy(obj);
		perror("uprobe_bpf__load");
		exit(1);
	}

	assert(obj->links.probe_unix_socket_sendmsg == NULL);

	err = uprobe_bpf__attach(obj);
	if (err) {
		perror("uprobe_bpf__attach");
		exit(1);
	}

	// obj->links.probe_unix_socket_sendmsg = bpf_program__attach_kprobe(obj->progs.probe_unix_socket_sendmsg, false, "unix_stream_sendmsg");

	printf("\nSuccessfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
              "to see output of the BPF programs.\n");

	while(1) {
		sleep(1);
	}
}
