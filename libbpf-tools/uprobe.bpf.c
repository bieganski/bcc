#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC(".data.symbol_name") static char symbol_name[64] = "MOCK_SYMBOL";
SEC(".data.library_path") static char library_path[128] = "MOCK_LIBRARY";

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define PERF_MAX_STACK_DEPTH 127

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
	__uint(max_entries, 1000);
} rb SEC(".maps");


#define BPF_BUILD_ID_SIZE 20
// struct bpf_stack_build_id {
// 	__s32		status;
// 	unsigned char	build_id[BPF_BUILD_ID_SIZE];
// 	union {
// 		__u64	offset;
// 		__u64	ip;
// 	};
// };

#include <bpf/bpf_core_read.h>


// that function exists only due to "funny" bpf_snprintf constraints.
static void _build_id_byteswap_for_snprintf(void* _ptr, int size) {
	char* ptr = (char*) _ptr;
	char temp;
	for(int i = 0 ; i < size / 2; i++) {
		temp = ptr[i];
		ptr[i] = ptr[size - 1 - i];
		ptr[size - 1 - i] = temp;
	}
}

static void build_id_byteswap_for_snprintf(void* _ptr) {
	_build_id_byteswap_for_snprintf(_ptr, 8);
	_build_id_byteswap_for_snprintf(_ptr+8, 8);
	_build_id_byteswap_for_snprintf(_ptr+16, 4);
}



SEC("uprobe//")
int BPF_KPROBE(uprobe_funcname, long long arg1, long long arg2, long long arg3, long long arg4, long long arg5, long long arg6)
{
	int pid = bpf_get_current_pid_tgid() >> 32;


#define MAX_STACK_DEPTH 3
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

	unsigned char buf[sizeof(struct bpf_stack_build_id) * MAX_STACK_DEPTH];
	struct bpf_stack_build_id *build_id = (struct bpf_stack_build_id *)buf;
	int err = bpf_get_stack (
		ctx,
		buf,
		bpf_core_type_size (struct bpf_stack_build_id) * MAX_STACK_DEPTH,
		BPF_F_USER_STACK | BPF_F_USER_BUILD_ID
	);
	
	if (err <= 0) {
      bpf_printk ("unable to extract build-id: %ld\n", err);
      return err;
    }

	if (err % 32 != 0) goto fail;
	
	int iters = err >> 5;
	bpf_printk("uprobe hit %s:%s from PID %d. args: %llx,%llx,%llx,%llx,%llx,%llx", library_path, symbol_name, pid, arg1, arg2, arg3, arg4, arg5, arg6);

	for (int i = 0; i < MAX_STACK_DEPTH; i++) {
		if (iters-- == 0) break;

		char printbuf[20 * 2];
		struct bpf_stack_build_id * cur_stack = &build_id[i];
		struct bpf_stack_build_id * cur_build_id = &(cur_stack->build_id);
		build_id_byteswap_for_snprintf(cur_build_id);
		bpf_snprintf(&printbuf[0], 20*2, "%lx%lx%x", cur_build_id, 24);
		bpf_printk("       %d: %s at offset %x", i, printbuf, cur_stack->offset);
	}

	bpf_printk("\n");
	return 0; 

fail:
	bpf_printk("BPF fail");
	return -22;
}

SEC("uprobe//")
int BPF_KRETPROBE(ret_uprobe_funcname, unsigned long ret)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("retprobe PID %d, ret value: 0x%lx", pid, ret); // PT_REGS_RC(regs)
	return 0;
}
