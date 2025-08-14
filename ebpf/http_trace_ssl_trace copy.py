from bcc import BPF
import ctypes as ct

# Define the BPF program
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
    int is_read;
    char data[MAX_MSG_SIZE];
};

BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(tmp_event, struct event_t, 1);

static __always_inline
int process_ssl_data(struct pt_regs *ctx, void *buf, size_t count, int is_read) {
    u32 zero = 0;
    struct event_t *event = tmp_event.lookup(&zero);
    if (!event)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->tid = (u32)pid_tgid;
    event->is_read = is_read;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    size_t copy_size = count < MAX_MSG_SIZE ? count : MAX_MSG_SIZE;
    event->msg_size = (u32)copy_size;

    bpf_probe_read_user(&event->data, copy_size, buf);

    events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

int ssl_write(struct pt_regs *ctx) {
    void *buf = (void *)PT_REGS_PARM2(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);
    
    if (count == 0 || count > MAX_MSG_SIZE)
        return 0;

    bpf_trace_printk("SSL_write called with %d bytes\\n", count);
    return process_ssl_data(ctx, buf, count, 0);
}

int ssl_read_return(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    if (ret <= 0)
        return 0;

    void *buf = (void *)PT_REGS_PARM2(ctx);
    bpf_trace_printk("SSL_read returned with %d bytes\\n", ret);
    return process_ssl_data(ctx, buf, ret, 1);
}
"""

# Load the BPF program
b = BPF(text=bpf_text)

# Attach uprobes
try:
    b.attach_uprobe(name="/usr/lib/x86_64-linux-gnu/libssl.so.3", sym="SSL_write", fn_name="ssl_write")
    b.attach_uretprobe(name="/usr/lib/x86_64-linux-gnu/libssl.so.3", sym="SSL_read", fn_name="ssl_read_return")
except Exception as e:
    print(f"Failed to attach probes: {e}")
    exit(1)

# Define the Python class for the event structure
class Event(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("tid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("msg_size", ct.c_uint32),
        ("is_read", ct.c_int),
        ("data", ct.c_char * 4096)
    ]

def print_debug_info():
    """Print debug info from kernel trace buffer"""
    while True:
        try:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
            print(f"Debug: {msg.decode()}")
        except KeyboardInterrupt:
            exit()
        except:
            break

# Callback function to process events
def process_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Event)).contents
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
        print(f"{'=' * 50}\n")
        
        # Print debug info
        print_debug_info()
        
    except Exception as e:
        print(f"Error processing event: {e}")

# Attach the callback to the perf buffer
b["events"].open_perf_buffer(process_event)

print("Tracing SSL read/write operations... Hit Ctrl-C to end.")

# Poll the perf buffer
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nExiting...")

# Clean up
b.cleanup()