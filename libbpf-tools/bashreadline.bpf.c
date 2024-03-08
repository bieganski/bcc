#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bashreadline.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(value_size, sizeof(int));
	__uint(key_size, sizeof(int));
} events SEC(".maps");


SEC("kretprobe/readline")
int BPF_KRETPROBE(printret, char* ret)
{
    bpf_printk("aaa %s\n", ret);
    return 0;
}