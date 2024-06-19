/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _UNIX_DUMP_H_
#define _UNIX_DUMP_H_

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define LOAD_CONSTANT(param, var) asm("%0 = " param " ll" : "=r"(var))

__attribute__((always_inline)) static u64 load_pid_filter() {
    u64 pid_filter = 0;
    LOAD_CONSTANT("pid_filter", pid_filter);
    return pid_filter;
}

__attribute__((always_inline)) static u64 load_comm_filter() {
    u64 comm_filter = 0;
    LOAD_CONSTANT("comm_filter", comm_filter);
    return comm_filter;
}

__attribute__((always_inline)) static u64 load_socket_filter() {
    u64 socket_filter = 0;
    LOAD_CONSTANT("socket_filter", socket_filter);
    return socket_filter;
}

#define PATH_MAX 255
#define TASK_COMM_LEN 16
#define MAX_SEGS_PER_MSG 100
#define MAX_SEG_SIZE 1024 * 50


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, char[TASK_COMM_LEN]);
	__type(value, u32);
	__uint(max_entries, 512);
} comm_filters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, char[PATH_MAX]);
	__type(value, u32);
	__uint(max_entries, 512);
} socket_filters SEC(".maps");

__attribute__((always_inline)) int is_process_ignored(u32 pid) {
    // check if comms are filtered
    if (load_comm_filter()) {
        char comm[TASK_COMM_LEN] = {};
        bpf_get_current_comm(&comm[0], TASK_COMM_LEN);
        u32 *filter = bpf_map_lookup_elem(&comm_filters, comm);
        if (filter == 0 || (filter != 0 && *filter != 1)) {
            // filter out event
            return 1;
        }
    }

    // check if pid is filtered
    u32 pid_filter = load_pid_filter();
    if (pid_filter > 0) {
        if (pid != pid_filter) {
            // filter out event
            return 1;
        }
    }
    return 0;
}

__attribute__((always_inline)) int is_socket_ignored(char path[PATH_MAX]) {
    if (load_socket_filter()) {
        u32 *filter = bpf_map_lookup_elem(&socket_filters, path);
        if (filter == 0 || (filter != 0 && *filter != 1)) {
            // filter out event
            return 1;
        }
    }
    return 0;
}

struct unix_event {
    u32 pid;
    u32 peer_pid;
    u32 packet_len;
    u32 socket_len;
    char comm[TASK_COMM_LEN];
    char data[PATH_MAX + MAX_SEG_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct unix_event);
	__uint(max_entries, 16);
} unix_event_gen SEC(".maps");

struct unix_event event_zero = {};

__attribute__((always_inline)) struct unix_event *new_unix_event() {
    u32 cpuID = bpf_get_smp_processor_id();
    int ret = bpf_map_update_elem(&unix_event_gen, &cpuID, &event_zero, BPF_ANY);
    if (ret < 0) {
        // should never happen
        return 0;
    }
    return bpf_map_lookup_elem(&unix_event_gen, &cpuID);
}

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16384 * 1024 /* 16 MB */);
} events SEC(".maps");

__attribute__((always_inline)) void send_unix_event(struct unix_event *event, u32 len) {
    bpf_ringbuf_output(&events, event, len, BPF_RB_FORCE_WAKEUP);
}




SEC("kprobe/unix_stream_sendmsg")
int kprobe_unix_stream_sendmsg(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    // check if process is filtered
    if (is_process_ignored(pid)) {
        return 0;
    }

    // create unix event
    struct unix_event *evt = new_unix_event();
    if (evt == 0) {
        return 0;
    }

    struct unix_sock *local = 0;
    struct unix_sock *peer = 0;
    struct socket *sock = (struct socket *) PT_REGS_PARM1(ctx);

    BPF_CORE_READ_INTO(&local, sock, sk);
    if (BPF_CORE_READ(local, addr, len) > 0) {
        evt->socket_len = BPF_CORE_READ_STR_INTO(&evt->data, local, addr, name[0].sun_path);
    }

    BPF_CORE_READ_INTO(&peer, local, peer);
    if (BPF_CORE_READ(peer, addr, len) > 0) {
        evt->socket_len = BPF_CORE_READ_STR_INTO(&evt->data, peer, addr, name[0].sun_path);
    }

    if (evt->socket_len >= PATH_MAX) {
        evt->socket_len = PATH_MAX;
    }

    // check if the local or peer socket is one of the filtered unix sockets
    if (is_socket_ignored(evt->data)) {
        return 0;
    }

    evt->pid = pid;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    evt->peer_pid = BPF_CORE_READ(sock, sk, sk_peer_pid, numbers[0].nr);

    // read message content
    struct msghdr *msg = (struct msghdr *) PT_REGS_PARM2(ctx);

    if ((BPF_CORE_READ(msg, msg_iter.iter_type) & 1) == 0 || BPF_CORE_READ(msg, msg_iter.iov_offset) != 0) {
        // ignore call
        return 0;
    }

    char *buf = 0;
    u32 len = 0;
    u64 segs_counter = 0;
    u64 nr_segs = 0;
    struct kvec *iov = 0;

    BPF_CORE_READ_INTO(&iov, msg, msg_iter.kvec);
    nr_segs = BPF_CORE_READ(msg, msg_iter.nr_segs);

    #pragma unroll
    for (int i = 0; i < MAX_SEGS_PER_MSG; i++) {
        evt->packet_len = BPF_CORE_READ(iov, iov_len);
        len = evt->packet_len;

        BPF_CORE_READ_INTO(&buf, iov, iov_base);
        bpf_probe_read_user_str(evt->data + (evt->socket_len > PATH_MAX ? PATH_MAX : evt->socket_len), len > sizeof(evt->data) - PATH_MAX ? sizeof(evt->data) - PATH_MAX : len, buf);

        len += offsetof(struct unix_event, data) + evt->socket_len;
        send_unix_event(evt, len > sizeof(*evt) ? sizeof(*evt) : len);

        iov++;
        segs_counter++;
        if (segs_counter >= nr_segs) {
            goto next;
        }
    }

next:
    return 0;
}

#endif