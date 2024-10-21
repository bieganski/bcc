#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC(".data.symbol_name") static char symbol_name[64] = "MOCK_SYMBOL";
SEC(".data.library_path") static char library_path[128] = "MOCK_LIBRARY";

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// SEC("uprobe//")
// int BPF_KPROBE(uprobe_funcname, long long arg1, long long arg2, long long arg3, long long arg4, long long arg5, long long arg6)
// {
// 	int pid = bpf_get_current_pid_tgid() >> 32;
// 	bpf_printk("uprobe hit %s:%s from PID %d. args: %llx,%llx,%llx,%llx,%llx,%llx", library_path, symbol_name, pid, arg1, arg2, arg3, arg4, arg5, arg6);
// 	return 0;
// }

// static void* cur_ptr;
// static unsigned long cur_size;

// #define printf bpf_printk

// static inline void DumpHex(const void* data, size_t size) {
// 	char ascii[17];
// 	size_t i, j;
// 	ascii[16] = '\0';
// 	for (i = 0; i < size; ++i) {
// 		// printf("%02X ", ((unsigned char*)data)[i]);
// 		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
// 			ascii[i % 16] = ((unsigned char*)data)[i];
// 		} else {
// 			ascii[i % 16] = '.';
// 		}
// 		if ((i+1) % 8 == 0 || i+1 == size) {
// 			// printf(" ");
// 			if ((i+1) % 16 == 0) {
// 				printf("|  %s", ascii);
// 			} else if (i+1 == size) {
// 				ascii[(i+1) % 16] = '\0';
// 				// if ((i+1) % 16 <= 8) {
// 				// 	printf(" ");
// 				// }
// 				// for (j = (i+1) % 16; j < 16; ++j) {
// 				// 	printf("   ");
// 				// }
// 				printf("|  %s", ascii);
// 			}
// 		}
// 	}
// }

// static int SSL_exit(struct pt_regs *ctx, int rw) {

// 	static char buf[4096];

// 	if (cur_size > 4096) {
// 		bpf_printk("AAAAAAAAAAa to much data %d\n", cur_size);
// 		// return 0;
// 		cur_size = 4096;
// 	}

// 	long ret = bpf_probe_read_user(buf, cur_size, (char *)cur_ptr);
// 	if (!ret) {
// 		buf[4096 - 1] = 0;
// 		bpf_printk("FINE!!! READ %d bytes!\n", ret);
// 		DumpHex(buf, 4096);
// 	} else {
// 		bpf_printk("BAD!!! READ 0 bytes!\n");
// 	}
// 	return 0;
// }

// SEC("uretprobe/SSL_read")
// int BPF_URETPROBE(probe_SSL_read_exit) {
//     return (SSL_exit(ctx, 0));
// }


// // int SSL_read(SSL *ssl, void *buf, int num);
// SEC("uretprobe/SSL_read")
// // int BPF_UPROBE(probe_SSL_read) {
// BPF_KPROBE(probe_SSL_read, long arg1, long arg2, long arg3) {
// 	cur_ptr = (void*) arg2;
// 	cur_size = arg3;
// 	return 0;
// }

// SEC("uretprobe/SSL_write")
// int BPF_URETPROBE(probe_SSL_write_exit) {
//     return (SSL_exit(ctx, 1));
// }

// int BPF_UPROBE(probe_SSL_read) {
SEC("uprobe//")
long BPF_KPROBE(probe_SSL_read, long arg1) {
	return arg1;
}
