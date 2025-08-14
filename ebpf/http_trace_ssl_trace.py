from bcc import BPF
import ctypes as ct
import sys
import os
import subprocess

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
    u32 is_java;
    u32 symbol_id;
    char data[MAX_MSG_SIZE];
};

BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(tmp_event, struct event_t, 1);

static __always_inline
int submit_event(struct pt_regs *ctx, void *buf, size_t count, u32 is_read, u32 is_java, u32 symbol_id) {
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
    event->is_read = is_read;
    event->is_java = is_java;
    event->symbol_id = symbol_id;
    event->msg_size = size;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_user(event->data, size & (MAX_MSG_SIZE - 1), buf);
    events.perf_submit(ctx, event, sizeof(*event));

    return 0;
}

// OpenSSL probes
int ssl_write(struct pt_regs *ctx) {
    void *buf = (void *)PT_REGS_PARM2(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);
    bpf_trace_printk("OpenSSL write: size=%u\\n", count);
    return submit_event(ctx, buf, count, 0, 0, 1);
}

int ssl_read_return(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    if (ret <= 0) {
        bpf_trace_printk("OpenSSL read return: ret=%d\\n", ret);
        return 0;
    }

    void *buf = (void *)PT_REGS_PARM2(ctx);
    bpf_trace_printk("OpenSSL read return: size=%u\\n", ret);
    return submit_event(ctx, buf, ret, 1, 0, 2);
}

// Java Socket probes
int socket_read(struct pt_regs *ctx) {
    void *buf = (void *)PT_REGS_PARM2(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);
    bpf_trace_printk("Socket read: size=%u\\n", count);
    return submit_event(ctx, buf, count, 1, 1, 3);
}

int socket_write(struct pt_regs *ctx) {
    void *buf = (void *)PT_REGS_PARM2(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);
    bpf_trace_printk("Socket write: size=%u\\n", count);
    return submit_event(ctx, buf, count, 0, 1, 4);
}

// Java GSS/SSL probes
int gss_wrap(struct pt_regs *ctx) {
    void *buf = (void *)PT_REGS_PARM2(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);
    bpf_trace_printk("GSS wrap: size=%u\\n", count);
    return submit_event(ctx, buf, count, 0, 1, 5);
}

int gss_unwrap(struct pt_regs *ctx) {
    void *buf = (void *)PT_REGS_PARM2(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);
    bpf_trace_printk("GSS unwrap: size=%u\\n", count);
    return submit_event(ctx, buf, count, 1, 1, 6);
}

// Java Net probes
int net_read(struct pt_regs *ctx) {
    void *buf = (void *)PT_REGS_PARM2(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);
    bpf_trace_printk("Net read: size=%u\\n", count);
    return submit_event(ctx, buf, count, 1, 1, 7);
}

int net_write(struct pt_regs *ctx) {
    void *buf = (void *)PT_REGS_PARM2(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);
    bpf_trace_printk("Net write: size=%u\\n", count);
    return submit_event(ctx, buf, count, 0, 1, 8);
}
"""

class Event(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("tid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("msg_size", ct.c_uint32),
        ("is_read", ct.c_uint32),
        ("is_java", ct.c_uint32),
        ("symbol_id", ct.c_uint32),
        ("data", ct.c_char * 4096)
    ]

def print_event_data(event):
    try:
        impl_type = "Java GSS" if event.symbol_id in [5, 6] else \
                   "Java Net" if event.symbol_id in [7, 8] else \
                   "Java Socket" if event.symbol_id in [3, 4] else "OpenSSL"
        operation = "READ" if event.is_read else "WRITE"
        symbol_names = {
            1: "SSL_write",
            2: "SSL_read",
            3: "Socket_read",
            4: "Socket_write",
            5: "GSS_wrap",
            6: "GSS_unwrap",
            7: "Net_read",
            8: "Net_write"
        }
        symbol = symbol_names.get(event.symbol_id, "Unknown")
        
        print(f"\n{'=' * 50}")
        print(f"Implementation: {impl_type}")
        print(f"Operation: {operation}")
        print(f"Symbol: {symbol}")
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

def print_debug_info(b):
    try:
        while True:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
            if msg == b"":
                break
            print(f"Debug: {msg.decode()}")
    except Exception:
        pass

def find_java_implementations():
    """Find Java implementations"""
    java_home = "/usr/lib/jvm/temurin-21-jdk-amd64"
    
    implementations = []
    
    # Check Socket implementation (NIO)
    nio_lib = os.path.join(java_home, "lib", "libnio.so")
    if os.path.exists(nio_lib):
        try:
            print(f"\nChecking NIO library: {nio_lib}")
            output = subprocess.check_output(['nm', '-D', nio_lib]).decode()
            socket_symbols = [
                'Java_sun_nio_ch_SocketDispatcher_read0',
                'Java_sun_nio_ch_SocketDispatcher_write0'
            ]
            
            found_symbols = []
            for sym in socket_symbols:
                if sym in output:
                    found_symbols.append(('socket', sym))
                    print(f"Found socket symbol: {sym}")
            
            if found_symbols:
                implementations.append(('socket', nio_lib, found_symbols))
        except Exception as e:
            print(f"Error checking NIO library: {e}")
    
    # Check Net implementation
    net_lib = os.path.join(java_home, "lib", "libnet.so")
    if os.path.exists(net_lib):
        try:
            print(f"\nChecking Net library: {net_lib}")
            output = subprocess.check_output(['nm', '-D', net_lib]).decode()
            net_symbols = [
                'Java_sun_nio_ch_Net_read',
                'Java_sun_nio_ch_Net_write'
            ]
            
            found_symbols = []
            for sym in net_symbols:
                if sym in output:
                    found_symbols.append(('net', sym))
                    print(f"Found net symbol: {sym}")
            
            if found_symbols:
                implementations.append(('net', net_lib, found_symbols))
        except Exception as e:
            print(f"Error checking Net library: {e}")
    
    # Check GSS implementation
    gss_lib = os.path.join(java_home, "lib", "libj2gss.so")
    if os.path.exists(gss_lib):
        try:
            print(f"\nChecking GSS library: {gss_lib}")
            output = subprocess.check_output(['nm', '-D', gss_lib]).decode()
            gss_symbols = [
                'Java_sun_security_jgss_wrapper_GSSLibStub_wrap',
                'Java_sun_security_jgss_wrapper_GSSLibStub_unwrap'
            ]
            
            found_symbols = []
            for sym in gss_symbols:
                if sym in output:
                    found_symbols.append(('gss', sym))
                    print(f"Found GSS symbol: {sym}")
            
            if found_symbols:
                implementations.append(('gss', gss_lib, found_symbols))
        except Exception as e:
            print(f"Error checking GSS library: {e}")
    
    return implementations

def main():
    # Load BPF program
    try:
        b = BPF(text=bpf_text)
    except Exception as e:
        print(f"Failed to load BPF program: {e}")
        sys.exit(1)

    # Attach OpenSSL probes
    try:
        b.attach_uprobe(name="/usr/lib/x86_64-linux-gnu/libssl.so.3", 
                       sym="SSL_write", fn_name="ssl_write")
        b.attach_uretprobe(name="/usr/lib/x86_64-linux-gnu/libssl.so.3", 
                          sym="SSL_read", fn_name="ssl_read_return")
        print("Successfully attached OpenSSL probes")
    except Exception as e:
        print(f"Failed to attach OpenSSL probes: {e}")

    # Find and attach Java implementations
    print("\nLooking for Java implementations...")
    implementations = find_java_implementations()
    
    for impl_type, lib_path, symbols in implementations:
        try:
            if impl_type == 'socket':
                for _, sym in symbols:
                    if 'read' in sym:
                        b.attach_uprobe(name=lib_path, sym=sym, fn_name="socket_read")
                        print(f"Attached socket read probe to {sym}")
                    elif 'write' in sym:
                        b.attach_uprobe(name=lib_path, sym=sym, fn_name="socket_write")
                        print(f"Attached socket write probe to {sym}")
            elif impl_type == 'net':
                for _, sym in symbols:
                    if 'read' in sym:
                        b.attach_uprobe(name=lib_path, sym=sym, fn_name="net_read")
                        print(f"Attached net read probe to {sym}")
                    elif 'write' in sym:
                        b.attach_uprobe(name=lib_path, sym=sym, fn_name="net_write")
                        print(f"Attached net write probe to {sym}")
            elif impl_type == 'gss':
                for _, sym in symbols:
                    if 'wrap' in sym:
                        b.attach_uprobe(name=lib_path, sym=sym, fn_name="gss_wrap")
                        print(f"Attached GSS wrap probe to {sym}")
                    elif 'unwrap' in sym:
                        b.attach_uprobe(name=lib_path, sym=sym, fn_name="gss_unwrap")
                        print(f"Attached GSS unwrap probe to {sym}")
        except Exception as e:
            print(f"Failed to attach {impl_type} probes to {lib_path}: {e}")

    # Attach perf buffer
    b["events"].open_perf_buffer(process_event)

    print("\nTracing SSL/TLS operations... Hit Ctrl-C to end.")

    try:
        while True:
            b.perf_buffer_poll()
            print_debug_info(b)
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        b.cleanup()

if __name__ == "__main__":
    main()