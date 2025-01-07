#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC(".data.symbol_name") static char symbol_name[64] = "MOCK_SYMBOL";
SEC(".data.library_path") static char library_path[128] = "MOCK_LIBRARY";

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// #define PERF_MAX_STACK_DEPTH 127

// struct {
// 	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
// 	__uint(key_size, sizeof(u32));
// 	__uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
// 	__uint(max_entries, 1000);
// } rb SEC(".maps");


/* BPF ringbuf map */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
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

struct event {
	
	// those below form userspace dict key
	char library_path[128];
	char symbol_name[64];
	int32_t pid;
	int32_t tid;

	unsigned long pc;
	unsigned long ret_addr;
	unsigned long ret_val;

	unsigned long arg1;
	unsigned long arg2;
	unsigned long arg3;
	unsigned long arg4;
	unsigned long arg5;
	unsigned long arg6;
	
	uint64_t timestamp;
	int32_t is_ret;
};
// library_path, symbol_name, pid, pc, arg1, arg2, arg3, arg4, arg5, arg6);

static inline void copy_regs(struct pt_regs* regs, struct event* e) {
	e->pc = PT_REGS_IP(regs);
	e->arg1 = PT_REGS_PARM1(regs);
	e->arg2 = PT_REGS_PARM2(regs);
	e->arg3 = PT_REGS_PARM3(regs);
	e->arg4 = PT_REGS_PARM4(regs);
	e->arg5 = PT_REGS_PARM5(regs);
	e->arg6 = PT_REGS_PARM6(regs);
	e->ret_addr = PT_REGS_RET(regs);
	e->ret_val = PT_REGS_RC(regs);
}

static inline void copy_pid_tid(struct pt_regs* regs, struct event* e) {
	uint64_t pid_tid = bpf_get_current_pid_tgid();
	int pid = pid_tid >> 32;
	int tid = (uint32_t) pid_tid;
	e->pid = pid;
	e->tid = tid;
}

SEC("uprobe//")
int BPF_KPROBE(uprobe_funcname)
{
	bpf_printk("is_ret=0");
	
	
	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	// fill 'struct event'.
	e->is_ret = 0;
	e->timestamp = bpf_ktime_get_ns();
	bpf_probe_read_kernel_str(e->library_path, 128, library_path);
	bpf_probe_read_kernel_str(e->symbol_name, 64, symbol_name);
	copy_pid_tid(ctx, e);
	copy_regs(ctx, e);

	bpf_ringbuf_submit(e, 0);

	return 0;


// #define MAX_STACK_DEPTH 3
// #define MIN(x, y) (((x) < (y)) ? (x) : (y))

// 	unsigned char buf[sizeof(struct bpf_stack_build_id) * MAX_STACK_DEPTH];
// 	struct bpf_stack_build_id *build_id = (struct bpf_stack_build_id *)buf;
// 	int err = bpf_get_stack (
// 		ctx,
// 		buf,
// 		bpf_core_type_size (struct bpf_stack_build_id) * MAX_STACK_DEPTH,
// 		BPF_F_USER_STACK | BPF_F_USER_BUILD_ID
// 	);
	
// 	if (err <= 0) {
//       bpf_printk ("unable to extract build-id: %ld\n", err);
//       return err;
//     }

// 	if (err % 32 != 0) goto fail;
	
// 	int iters = err >> 5;
// 	unsigned long pc = PT_REGS_IP(ctx);
// 	bpf_printk("uprobe hit %s:%s from PID %d (PC: %lx) args: %llx,%llx,%llx,%llx,%llx,%llx", library_path, symbol_name, pid, pc, arg1, arg2, arg3, arg4, arg5, arg6);

// 	for (int i = 0; i < MAX_STACK_DEPTH; i++) {
// 		if (iters-- == 0) break;

// 		char printbuf[20 * 2];
// 		struct bpf_stack_build_id * cur_stack = &build_id[i];
// 		struct bpf_stack_build_id * cur_build_id = &(cur_stack->build_id);
// 		build_id_byteswap_for_snprintf(cur_build_id);
// 		bpf_snprintf(&printbuf[0], 20*2, "%lx%lx%x", cur_build_id, 24);
// 		bpf_printk("       %d: %s at offset %x", i, printbuf, cur_stack->offset);
// 	}

// 	bpf_printk("\n");
// 	return 0; 

// fail:
// 	bpf_printk("BPF fail");
// 	return -22;
}

SEC("uprobe//")
int BPF_KRETPROBE(ret_uprobe_funcname) // , struct pt_regs* regs /* , unsigned long ret */)
{
	bpf_printk("is_ret=1");
	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	// fill 'struct event'.
	e->is_ret = 1;
	e->timestamp = bpf_ktime_get_ns();
	bpf_probe_read_kernel_str(e->library_path, 128, library_path);
	bpf_probe_read_kernel_str(e->symbol_name, 64, symbol_name);
	copy_pid_tid(ctx, e);
	copy_regs(ctx, e);

	bpf_ringbuf_submit(e, 0);
}
