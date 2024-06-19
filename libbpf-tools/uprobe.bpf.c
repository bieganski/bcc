// // SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// /* Copyright (c) 2020 Facebook */
// // #include "vmlinux.h"
// #include "vmlinux.h"
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>

// char LICENSE[] SEC("license") = "Dual BSD/GPL";

// // SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:write")
// SEC("uprobe//")
// int BPF_KPROBE(xdddwrite, long long arg1, long long arg2, long long arg3, long long arg4, long long arg5, long long arg6)
// {
// 	// static int divider = 0;

// 	// if (++divider & 0xf00)
// 	// 	bpf_printk("WRITE %d\n", fd);

// 	int pid = bpf_get_current_pid_tgid() >> 32;

// 	bpf_printk("generic uprobe hit from PID %d. args: %llx,%llx,%llx,%llx,%llx,%llx", pid, arg1, arg2, arg3, arg4, arg5, arg6);
// 	return 0;
// }


#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "Dual BSD/GPL";

// #include <linux/sched.h>
// #include <linux/net.h>
// #include <linux/un.h>
// // #include <net/af_unix.h>
// #include <linux/version.h>
// #include <linux/sched.h>
// #include <stdlib.h>

// TASK_COMM_LEN = 16
// UNIX_PATH_MAX = 108

// SS_MAX_SEG_SIZE = 1024 * 50
// SS_MAX_SEGS_PER_MSG = 10
// SS_MAX_SEGS_IN_BUFFER = 100

// SS_PACKET_F_ERR = 1

// #define TASK_COMM_LEN 16

#define SS_MAX_SEG_SIZE     (1024 * 50)
#define SS_MAX_SEGS_PER_MSG 10

#define UNIX_PATH_MAX 108

#define SS_PACKET_F_ERR     1

#define SOCK_PATH_OFFSET    \
    (offsetof(struct unix_address, name) + offsetof(struct sockaddr_un, sun_path))

#define u32 unsigned long
#define size_t int

struct packet {
    u32 pid;
    u32 peer_pid;
    u32 len;
    u32 flags;
    char comm[TASK_COMM_LEN];
    char path[UNIX_PATH_MAX];
    char data[SS_MAX_SEG_SIZE];
};

// TODO unknown
#define __PATH_LEN_U64__ 30

#define __PATH_LEN__ (UNIX_PATH_MAX -1 )

// use regular array instead percpu array because
// percpu array element size cannot be larger than 3k
// BPF_ARRAY(packet_array, struct packet, __NUM_CPUS__);

#define __NUM_CPUS__ 20

// struct {
//  __uint(type, BPF_MAP_TYPE_ARRAY);
//  __uint(max_entries, __NUM_CPUS__);
//  __type(key, int);
//  __type(value, struct packet);
// } events SEC(".maps");

struct {
 __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
 __uint(value_size, 4);
 __uint(key_size, 4);
} events SEC(".maps");


// BPF_PERF_OUTPUT(events);


volatile const int is_bpf_jiffies64_supported;

// SEC("kprobe/sendmsg")
SEC("kprobe/unix_stream_sendmsg")
int BPF_KPROBE(probe_unix_socket_sendmsg,
    struct socket * sock,
    struct msghdr *msg,
    size_t len)
{

    // bpf_printk("AAA");
    // return (int) BPF_CORE_READ(sock, sk);

    struct packet *packet;
    struct unix_address *addr;
    char *buf, *sock_path;
    unsigned long path[__PATH_LEN_U64__] = {0};
    unsigned int n, match = 0, offset;
    struct iov_iter *iter;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
    const struct iovec *iov;
#else
    const struct kvec *iov;
#endif
    struct pid *peer_pid;

    // addr = ((struct unix_sock *)sock->sk)->addr;

    struct unix_sock *sk = (struct unix_sock *) BPF_CORE_READ(sock, sk);

    addr = BPF_CORE_READ(sk, addr);

    size_t addr_len = BPF_CORE_READ(addr, len);

    if (addr_len > 0) {
        sock_path = (char *)addr + SOCK_PATH_OFFSET;
        bpf_probe_read(&path, sizeof(unsigned long), sock_path);
        if (*(char*)path == 0) {
            // abstract sockets start with \\0 and the name comes after
            // (they actually have no @ prefix but some tools use that)
            bpf_probe_read(&path, __PATH_LEN__ - 1, sock_path + 1);
        } else {
            bpf_probe_read(&path, __PATH_LEN__, sock_path);
        }
        // mateusz __PATH_FILTER__
		match = 1;
    }

    if (match == 0) {
        struct unix_sock* peer = (struct unix_sock *) BPF_CORE_READ(sk, peer);
        addr = BPF_CORE_READ(peer, addr);
        addr_len = BPF_CORE_READ(addr, len);
        
        if (addr_len > 0) {
            sock_path = (char *)addr + SOCK_PATH_OFFSET;
            bpf_probe_read(&path, sizeof(unsigned long), sock_path);
            if (*(char*)path == 0) {
                // abstract sockets start with \\0 and the name comes after
                // (they actually have no @ prefix but some tools use that)
                bpf_probe_read(&path, __PATH_LEN__ - 1, sock_path + 1);
            } else {
                bpf_probe_read(&path, __PATH_LEN__, sock_path);
            }
            // mateusz __PATH_FILTER__
            match = 1;
        }
    }

    if (match == 0)
        return 0;

    n = bpf_get_smp_processor_id();
    // mateusz: packet = packet_array.lookup(&n);
	packet = bpf_perf_event_read_value(&events, BPF_F_CURRENT_CPU, packet, sizeof(packet));

    if (packet == NULL)
        return 0;

    packet->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&packet->comm, sizeof(packet->comm));
    bpf_probe_read(&packet->path, UNIX_PATH_MAX, sock_path);
    // packet->peer_pid = sock->sk->sk_peer_pid->numbers->nr;
    struct upid numbers = *BPF_CORE_READ(sock, sk, sk_peer_pid, numbers);
    packet->peer_pid = numbers.nr;

    // mateusz __PID_FILTER__

    iter = &msg->msg_iter;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
#error not yet ported
    if (iter->iter_type == ITER_UBUF) {
        packet->len = len;
        packet->flags = 0;
        buf = iter->ubuf;
        n = len;

        bpf_probe_read(
            &packet->data,
            // check size in args to make compiler/validator happy
            n > sizeof(packet->data) ? sizeof(packet->data) : n,
            buf);

        n += offsetof(struct packet, data);

		bpf_perf_event_output(ctx, &events,
				BPF_F_CURRENT_CPU,
				packet, n > sizeof(*packet) ? sizeof(*packet) : n);
				
        // events.perf_submit(
        //     ctx,
        //     packet,
        //     // check size in args to make compiler/validator happy
        //     n > sizeof(*packet) ? sizeof(*packet) : n);

        return 0;
    }

    if (iter->iter_type != ITER_IOVEC || iter->iov_offset != 0) {
#else
    if (BPF_CORE_READ(iter, iov_offset) != 0) {
#endif
        packet->len = len;
        packet->flags = SS_PACKET_F_ERR;
        // events.perf_submit(ctx, packet, offsetof(struct packet, data));

		bpf_perf_event_output(ctx, &events,
				BPF_F_CURRENT_CPU,
				packet, offsetof(struct packet, data));

        return 0;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
    iov = iter->__iov;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
    iov = iter->iov;
#else
    iov = iter->kvec;
#endif

    #pragma unroll
    for (int i = 0; i < SS_MAX_SEGS_PER_MSG; i++) {
        if (i >= iter->nr_segs)
            break;

        packet->len = iov->iov_len;
        packet->flags = 0;

        buf = iov->iov_base;
        n = iov->iov_len;
        bpf_probe_read(
            &packet->data,
            // check size in args to make compiler/validator happy
            n > sizeof(packet->data) ? sizeof(packet->data) : n,
            buf);

        n += offsetof(struct packet, data);
        // events.perf_submit(
        //     ctx,
        //     packet,
        //     // check size in args to make compiler/validator happy
        //     n > sizeof(*packet) ? sizeof(*packet) : n);

		bpf_perf_event_output(ctx, &events,
				BPF_F_CURRENT_CPU,
				packet, n > sizeof(*packet) ? sizeof(*packet) : n);
				

        iov++;
    }

    return 0;
}
