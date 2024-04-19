// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
// #include "vmlinux.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:write")
SEC("uprobe//")
int BPF_KPROBE(xdddwrite, long long arg1, long long arg2, long long arg3, long long arg4, long long arg5, long long arg6)
{
	// static int divider = 0;

	// if (++divider & 0xf00)
	// 	bpf_printk("WRITE %d\n", fd);

	int pid = bpf_get_current_pid_tgid() >> 32;

	bpf_printk("generic uprobe hit from PID %d. args: %llx,%llx,%llx,%llx,%llx,%llx", pid, arg1, arg2, arg3, arg4, arg5, arg6);
	return 0;
}
