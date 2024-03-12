#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bashreadline.h"

char LICENSE[] SEC("license") = "GPL";

// int SSL_write_ex(SSL *s, const void *buf, size_t num, size_t *written);
#define NUM 1000

#define MIN(a,b) (((a)<(b))?(a):(b))

static char array[NUM] ={0};


struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	/* function call stack for functions we are tracing */
	__uint(max_entries, 100);
	// __type(key, __u64);
	// __type(value, struct func_stack);
	__uint(value_size, sizeof(array));
	__uint(key_size, 0);
	// .flags = BPF_F_QUEUE_FIFO, // https://patchwork.ozlabs.org/project/netdev/patch/153356392410.6981.1290059578982921349.stgit@kernel/#1969518
} events SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
// 	// __type(value, struct func_stack);

// 	__uint(value_size, sizeof(array));
// 	__uint(key_size, sizeof(int));
// } events SEC(".maps");


SEC("uprobe/foo")
int BPF_KPROBE(printret, void *ss, void *buf, size_t num) // size_t *written
{
	//       long bpf_probe_read_user(void *dst, u32 size, const void
    //    *unsafe_ptr)

    //           Description
    //                  Safely attempt to read size bytes from user space
    //                  address unsafe_ptr and store the data in dst.

	int real_num = MIN(NUM, num - 1);
	bpf_probe_read_user(array, real_num, buf);

	const u32 tid = bpf_get_current_pid_tgid();
	bpf_map_push_elem(&events, &array, BPF_EXIST);
	
    bpf_printk("GOT %d\n", num);
    return 0;
}

// SEC("uprobe/SSL_read_ex")
// int BPF_URETPROBE(printret2, char* ret)
// {
//     bpf_printk("bbb %s\n", ret);
//     return 0;
// }