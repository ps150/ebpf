from bcc import BPF
import ctypes as ct
import socket
import struct
import time

bpf_text = """
#include <linux/sched.h>
#include <linux/uio.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <linux/string.h>

#define MAX_DATA_SIZE 8192
#define TARGET_PORT 8080

struct data_buf_t {
    u32 buf_len;
    u32 _padding;
    char data[MAX_DATA_SIZE];
} __attribute__((aligned(8)));

struct event_t {
    u32 pid;
    u32 tid;
    u16 sport;
    u16 dport;
    u32 data_len;
    u32 saddr;
    u32 daddr;
    char comm[TASK_COMM_LEN];
    u8 _padding;
    bool is_send;
} __attribute__((aligned(8)));

BPF_PERCPU_ARRAY(data_buffer, struct data_buf_t, 1);
BPF_PERF_OUTPUT(events);

static inline bool should_trace(u16 dport, u16 sport) {
    return (dport == TARGET_PORT || sport == TARGET_PORT ||
            dport == 80 || sport == 80 ||
            dport == 443 || sport == 443);
}

static int trace_message(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size, bool is_send)
{
    if (!sk || !msg || size == 0 || size > MAX_DATA_SIZE)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct event_t event = {};
    event.pid = pid_tgid >> 32;
    event.tid = (u32)pid_tgid;

    bpf_probe_read_kernel(&event.dport, sizeof(event.dport), &sk->__sk_common.skc_dport);
    bpf_probe_read_kernel(&event.sport, sizeof(event.sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_rcv_saddr);

    event.dport = ntohs(event.dport);
    event.sport = ntohs(event.sport);

    if (!should_trace(event.dport, event.sport)) {
        return 0;
    }

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.is_send = is_send;
    event.data_len = size;

    int zero = 0;
    struct data_buf_t *buffer = data_buffer.lookup(&zero);
    if (!buffer) {
        return 0;
    }

    buffer->buf_len = 0;

    struct iov_iter iter;
    bpf_probe_read_kernel(&iter, sizeof(iter), &msg->msg_iter);

    if (iter.count > 0 && iter.count <= MAX_DATA_SIZE) {
        const struct iovec *iov;
        bpf_probe_read_kernel(&iov, sizeof(iov), &iter.iov);
        
        if (iov) {
            struct iovec first_iov;
            bpf_probe_read_kernel(&first_iov, sizeof(first_iov), iov);
            
            if (first_iov.iov_base && first_iov.iov_len > 0 && first_iov.iov_len <= MAX_DATA_SIZE) {
                u32 read_len = first_iov.iov_len;
                read_len = read_len > MAX_DATA_SIZE ? MAX_DATA_SIZE : read_len;
                
                if (read_len > 0 && read_len <= MAX_DATA_SIZE) {
                    int ret = bpf_probe_read_user(buffer->data, read_len, first_iov.iov_base);
                    if (ret == 0) {
                        buffer->buf_len = read_len;
                        event.data_len = read_len;
                    }
                }
            }
        }
    }

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size)
{
    return trace_message(ctx, sk, msg, size, true);
}

int trace_tcp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len)
{
    return trace_message(ctx, sk, msg, len, false);
}
"""
class Event(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("tid", ct.c_uint32),
        ("sport", ct.c_uint16),
        ("dport", ct.c_uint16),
        ("data_len", ct.c_uint32),
        ("saddr", ct.c_uint32),
        ("daddr", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("_padding", ct.c_uint8),
        ("is_send", ct.c_uint8)
    ]

class DataEvent(ct.Structure):
    _fields_ = [
        ("data", ct.c_char * 8192)
    ]

def format_http_data(data_str):
    try:
        parts = data_str.split('\r\n\r\n', 1)
        if len(parts) < 2:
            return data_str

        headers, body = parts
        formatted_output = []

        header_lines = headers.split('\r\n')
        if header_lines:
            formatted_output.append(header_lines[0])
            formatted_output.append("\nHeaders:")
            for header in header_lines[1:]:
                if header:
                    formatted_output.append(f"  {header}")

        if body:
            formatted_output.append("\nBody:")
            formatted_output.append(body)

        return '\n'.join(formatted_output)
    except Exception:
        return data_str

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Event)).contents
    
    if event.is_send:
        direction = "→"
        print("\n============================================================")
        print(f"{direction} HTTP Request")
    else:
        direction = "←"
        print("\n============================================================")
        print(f"{direction} HTTP Response")

    print(f"Process: {event.comm.decode('utf-8', 'replace').strip()} (PID: {event.pid})")
    src_addr = socket.inet_ntoa(struct.pack("I", event.saddr))
    dst_addr = socket.inet_ntoa(struct.pack("I", event.daddr))
    print(f"Source: {src_addr}:{event.sport}")
    print(f"Destination: {dst_addr}:{event.dport}")
    print(f"Data Length: {event.data_len} bytes")
    print("------------------------------------------------------------")

    try:
        data = b["data_map"][ct.c_uint32(event.tid)]
        if event.data_len > 0:
            data_str = data.data[:event.data_len].decode('utf-8', 'replace')
            print(format_http_data(data_str))
        else:
            print("<No Content>")
    except Exception as e:
        print(f"<Error decoding content: {str(e)}>")
    print("============================================================\n")

def main():
    global b
    b = BPF(text=bpf_text)
    b.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")
    b.attach_kprobe(event="tcp_recvmsg", fn_name="trace_tcp_recvmsg")

    print("Tracing HTTP traffic for ports 8080, 80, 443...")
    print("Make sure your application is running and generating traffic...")

    b["events"].open_perf_buffer(print_event)
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    main()
