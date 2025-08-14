from bcc import BPF
import ctypes as ct
import sys

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/limits.h>

#define MAX_MSG_SIZE 4096
#define TASK_COMM_LEN 16

struct event_t {
    u32 pid;
    u32 tid;
    char comm[TASK_COMM_LEN];
    u32 msg_size;
    u32 is_read;
    char data[MAX_MSG_SIZE];
};

// Store SSL read arguments
struct ssl_args_t {
    void *buf;
    size_t size;
};

BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(tmp_event, struct event_t, 1);
BPF_HASH(active_ssl_read_args, u64, struct ssl_args_t);

int ssl_write(struct pt_regs *ctx) {
    void *buf = (void *)PT_REGS_PARM2(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);
    
    u32 size = count & (MAX_MSG_SIZE - 1);
    if (!buf || size == 0)
        return 0;

    u32 zero = 0;
    struct event_t *event = tmp_event.lookup(&zero);
    if (!event)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->tid = (u32)pid_tgid;
    event->is_read = 0;
    event->msg_size = size;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_user(event->data, size & (MAX_MSG_SIZE - 1), buf);
    events.perf_submit(ctx, event, sizeof(*event));

    return 0;
}

int ssl_read_enter(struct pt_regs *ctx) {
    void *buf = (void *)PT_REGS_PARM2(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);
    
    struct ssl_args_t args = {};
    args.buf = buf;
    args.size = count;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    active_ssl_read_args.update(&pid_tgid, &args);
    
    return 0;
}

int ssl_read_return(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    if (ret <= 0)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args_t *args = active_ssl_read_args.lookup(&pid_tgid);
    if (!args)
        return 0;

    void *buf = args->buf;
    if (!buf)
        return 0;

    u32 size = ((u32)ret) & (MAX_MSG_SIZE - 1);
    if (size == 0)
        return 0;

    u32 zero = 0;
    struct event_t *event = tmp_event.lookup(&zero);
    if (!event)
        return 0;

    event->pid = pid_tgid >> 32;
    event->tid = (u32)pid_tgid;
    event->is_read = 1;
    event->msg_size = size;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_user(event->data, size & (MAX_MSG_SIZE - 1), buf);
    events.perf_submit(ctx, event, sizeof(*event));

    active_ssl_read_args.delete(&pid_tgid);
    return 0;
}
"""

class Event(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("tid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("msg_size", ct.c_uint32),
        ("is_read", ct.c_uint32),
        ("data", ct.c_char * 4096)
    ]

def print_event_data(event):
    try:
        method = "SSL_READ" if event.is_read else "SSL_WRITE"
        print(f"\n{'=' * 50}")
        print(f"Method: {method}")
        print(f"PID: {event.pid}, TID: {event.tid}")
        print(f"Process: {event.comm.decode()}")
        print(f"Data Size: {event.msg_size} bytes")
        print(f"{'=' * 50}")
        print("Data:")
        print(event.data[:event.msg_size].decode(errors='replace'))
        print(f"{'=' * 50}")
    except Exception as e:
        print(f"Error processing event: {e}")

def process_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Event)).contents
    print_event_data(event)

def main():
    # Load BPF program
    try:
        b = BPF(text=bpf_text)
    except Exception as e:
        print(f"Failed to load BPF program: {e}")
        sys.exit(1)

    # Try multiple SSL library paths
    ssl_paths = [
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
        "/usr/lib64/libssl.so.3"
    ]

    attached = False
    for ssl_path in ssl_paths:
        try:
            b.attach_uprobe(name=ssl_path, sym="SSL_write", fn_name="ssl_write")
            b.attach_uprobe(name=ssl_path, sym="SSL_read", fn_name="ssl_read_enter")
            b.attach_uretprobe(name=ssl_path, sym="SSL_read", fn_name="ssl_read_return")
            print(f"Successfully attached probes to {ssl_path}")
            attached = True
            break
        except Exception as e:
            continue

    if not attached:
        print("Failed to attach to any SSL library")
        sys.exit(1)

    # Attach perf buffer
    b["events"].open_perf_buffer(process_event)

    print("Tracing SSL read/write operations... Hit Ctrl-C to end.")

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        b.cleanup()

if __name__ == "__main__":
    main()