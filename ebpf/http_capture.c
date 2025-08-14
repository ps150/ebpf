#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/uio.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <bcc/proto.h>

#define MAX_CHUNK_SIZE 256

struct event {
    u32 pid;
    u16 port;
    u32 msg_size;
    u32 iov_len;
    u64 iov_base;
    char data[MAX_CHUNK_SIZE];
};

BPF_PERF_OUTPUT(events);

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size)
{
    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    
    if (ntohs(dport) != 8080)
        return 0;

    struct event e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.port = ntohs(dport);
    e.msg_size = size;

    struct iov_iter iter;
    bpf_probe_read_kernel(&iter, sizeof(iter), &msg->msg_iter);

    const struct iovec *iov;
    bpf_probe_read_kernel(&iov, sizeof(iov), &iter.iov);
    
    if (iov) {
        struct iovec first_iov;
        bpf_probe_read_kernel(&first_iov, sizeof(first_iov), iov);
        
        e.iov_len = first_iov.iov_len;
        e.iov_base = (u64)first_iov.iov_base;

        if (first_iov.iov_base && first_iov.iov_len > 0) {
            u32 read_len = first_iov.iov_len > sizeof(e.data) ? sizeof(e.data) : first_iov.iov_len;
            bpf_probe_read_user(e.data, read_len, first_iov.iov_base);
        }
    }

    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}