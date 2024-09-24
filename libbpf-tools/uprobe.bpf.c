#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC(".data.symbol_name") static char symbol_name[64] = "MOCK_SYMBOL";
SEC(".data.library_path") static char library_path[128] = "MOCK_LIBRARY";

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("uprobe//")
int BPF_KPROBE(uprobe_funcname, long long arg1, long long arg2, long long arg3, long long arg4, long long arg5, long long arg6)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("uprobe hit %s:%s from PID %d. args: %llx,%llx,%llx,%llx,%llx,%llx", library_path, symbol_name, pid, arg1, arg2, arg3, arg4, arg5, arg6);
	return 0;
}
