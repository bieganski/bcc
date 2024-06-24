// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "uprobe.skel.h"

#include <assert.h>
#include <time.h>
#include <signal.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}


#define SS_MAX_SEG_SIZE     (1024 * 50)
#define SS_MAX_SEGS_PER_MSG 10

#define UNIX_PATH_MAX 108

#define SS_PACKET_F_ERR     1

#define SOCK_PATH_OFFSET    \
    (offsetof(struct unix_address, name) + offsetof(struct sockaddr_un, sun_path))


#define TASK_COMM_LEN 16  // TODO TODO not confirmed!!!

struct packet {
    __u32 pid;
    __u32 peer_pid;
    __u32 len;
    __u32 flags;
	char data[SS_MAX_SEG_SIZE];
    char comm[TASK_COMM_LEN];
    char path[UNIX_PATH_MAX];
};

#include <fcntl.h>

void print_readable_characters(const char *array, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        if (array[i] >= 32 && array[i] <= 126) {
            printf("%c", array[i]);
        }
    }
}

// typedef int (*ring_buffer_sample_fn)(void *ctx, void *data, size_t size);
int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct packet *packet = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	char peer_comm[32] = "<unknown>";
	char filepath[256] = {0};
	snprintf(filepath, 256, "/proc/%d/comm", packet->peer_pid);
	int fd = open(filepath, O_RDONLY);
	int read_res = read(fd, peer_comm, 32);
	if (read_res > 0) {
		for(int i = 0; i < strlen(peer_comm); i++) {
			if (peer_comm[i] == 10)
				peer_comm[i] = 0;
		}
		// peer_comm[strlen(peer_comm) - 1] = '\0'; // strip newline
	}
	close(fd);

	if (packet->flags == SS_PACKET_F_ERR) {
		printf("PIPE ERROR !!!\n");
		return 0;
	}

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	printf("%-8s %s [%d -> %d] [%s -> %s] %s", ts, "PIPE", packet->pid, packet->peer_pid, packet->comm, peer_comm, packet->path);

	if (strlen(packet->data) == packet->len) {
		printf(" data_strlen %d ==: %s", packet->len, packet->data);
	} else {
		printf(" data_strlen %d != ", packet->len);
		print_readable_characters(packet->data, packet->len);
		// for (int i = 0; i < packet->len; i++) {
		// 	if (i % 8 == 0) {
		// 		printf("\n	");
		// 	}
		// 	printf("0x%x ", (unsigned char) packet->data[i]);
		// }
		// printf("\n");
	}
	printf("\n");
	return 0;
}

void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

int main(int argc, char **argv)
{

	/* Set up libbpf logging callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to create BPF maps */
	bump_memlock_rlimit();

	/* Clean handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

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



	struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(obj->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Process events */
	printf("%-8s %-5s %-7s %-16s %s\n",
	       "TIME", "EVENT", "PID", "COMM", "FILENAME");
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);

	return err < 0 ? -err : 0;
}
