#!/usr/bin/python3
from bcc import BPF
import ctypes as ct
import time
import socket
import struct
import json
import resource
import datetime
import re

# Define the structure for ctypes
class HttpEvent(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("direction", ct.c_uint8),      # 0 for send (request), 1 for recv (response)
        ("dport", ct.c_uint16),         # Destination port
        ("sport", ct.c_uint16),         # Source port
        ("saddr", ct.c_uint32),         # Source address
        ("daddr", ct.c_uint32),         # Destination address
        ("payload_len", ct.c_uint32),
        ("payload", ct.c_ubyte * 8192)  # Buffer for HTTP payload
    ]

# eBPF program
bpf_text = """
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/net.h>
#include <linux/uio.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bcc/proto.h>

#define MAX_BUF_SIZE 8192
#define DIRECTION_SEND 0
#define DIRECTION_RECV 1

struct http_event_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u8 direction;        // 0 for send, 1 for recv
    u16 dport;           // Destination port
    u16 sport;           // Source port
    u32 saddr;           // Source address
    u32 daddr;           // Destination address
    u32 payload_len;
    unsigned char payload[MAX_BUF_SIZE];
};

// Structure to pass data between entry and return probes
struct tcp_data_args_t {
    struct msghdr *msg;
    struct sock *sk;     // Socket info
    size_t size;         // Size for tcp_sendmsg
};

BPF_RINGBUF_OUTPUT(events, 32 * 4096);
BPF_HASH(tcp_sendmsg_args, u64, struct tcp_data_args_t);
BPF_HASH(tcp_recvmsg_args, u64, struct tcp_data_args_t);

// Extract socket information and populate event fields
static inline void get_socket_info(struct sock *sk, struct http_event_t *event) {
    // Get source and destination ports
    u16 sport = 0, dport = 0;
    u32 saddr = 0, daddr = 0;
    
    bpf_probe_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    bpf_probe_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    
    event->sport = sport;
    // Convert from network byte order
    event->dport = __builtin_bswap16(dport);
    event->saddr = saddr;
    event->daddr = daddr;
}

// Function to trace outgoing TCP messages (HTTP requests)
int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size)
{
    u64 id = bpf_get_current_pid_tgid();
    struct tcp_data_args_t args = {};
    args.msg = msg;
    args.sk = sk;
    args.size = size;
    
    if (size > 0) {
        const struct iovec *iov;
        bpf_probe_read(&iov, sizeof(iov), &msg->msg_iter.iov);
        if (iov) {
            void *base;
            bpf_probe_read(&base, sizeof(base), &iov->iov_base);
            if (base) {
                struct http_event_t *event;
                event = events.ringbuf_reserve(sizeof(struct http_event_t));
                if (!event)
                    return 0;
                    
                event->pid = id >> 32;
                event->direction = DIRECTION_SEND;
                bpf_get_current_comm(&event->comm, sizeof(event->comm));
                
                // Get socket info
                get_socket_info(sk, event);
                
                event->payload_len = size;
                u32 read_size = size;
                if (read_size > MAX_BUF_SIZE)
                    read_size = MAX_BUF_SIZE;
                    
                bpf_probe_read(&event->payload, read_size, base);
                events.ringbuf_submit(event, 0);
            }
        }
    }
    
    tcp_sendmsg_args.update(&id, &args);
    return 0;
}

// Store the msghdr pointer when tcp_recvmsg is called
int trace_tcp_recvmsg_entry(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, int flags)
{
    u64 id = bpf_get_current_pid_tgid();
    struct tcp_data_args_t args = {};
    args.msg = msg;
    args.sk = sk;
    tcp_recvmsg_args.update(&id, &args);
    return 0;
}

// Retrieve data after tcp_recvmsg finishes
int trace_tcp_recvmsg_ret(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct tcp_data_args_t *args = tcp_recvmsg_args.lookup(&id);
    if (!args)
        return 0;
        
    // Cast to u32 to ensure positive values for the verifier
    u32 ret = (u32)PT_REGS_RC(ctx);
    // Skip if return value is 0 (no data)
    if (ret == 0)
        goto cleanup;
        
    struct msghdr *msg = args->msg;
    if (!msg)
        goto cleanup;
        
    struct http_event_t *event;
    event = events.ringbuf_reserve(sizeof(struct http_event_t));
    if (!event)
        goto cleanup;
        
    event->pid = id >> 32;
    event->direction = DIRECTION_RECV;
    event->payload_len = ret;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // Get socket info
    get_socket_info(args->sk, event);
    
    struct iovec *iov;
    bpf_probe_read(&iov, sizeof(iov), &msg->msg_iter.iov);
    if (!iov) {
        events.ringbuf_discard(event, 0);
        goto cleanup;
    }
    
    void *base;
    bpf_probe_read(&base, sizeof(base), &iov->iov_base);
    if (!base) {
        events.ringbuf_discard(event, 0);
        goto cleanup;
    }
    
    // Ensure size is bounded for BPF verifier
    u32 read_size = ret;
    if (read_size > MAX_BUF_SIZE)
        read_size = MAX_BUF_SIZE;
        
    bpf_probe_read(&event->payload, read_size, base);
    events.ringbuf_submit(event, 0);
    
cleanup:
    tcp_recvmsg_args.delete(&id);
    return 0;
}
"""

def ip_to_str(addr):
    """Convert IP address to string format."""
    return socket.inet_ntoa(struct.pack("<I", addr))

def extract_http_info(payload_str):
    """Extract HTTP method, URL path, and host from HTTP payload."""
    http_method = None
    url_path = None
    host = None
    
    # Extract method and path from first line of request
    first_line_match = re.match(r'(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT)\s+([^\s]+)\s+HTTP', payload_str)
    if first_line_match:
        http_method = first_line_match.group(1)
        url_path = first_line_match.group(2)
    
    # Extract host from Host header
    host_match = re.search(r'Host:\s*([^\r\n]+)', payload_str, re.IGNORECASE)
    if host_match:
        host = host_match.group(1).strip()
    
    return http_method, url_path, host

def print_event(cpu, data, size):
    # Use the defined structure
    event = ct.cast(data, ct.POINTER(HttpEvent)).contents
    if event.payload_len > 0:
        try:
            payload = bytes(event.payload[:event.payload_len])
            payload_str = payload.decode('utf-8', errors='replace')
            
            # HTTP detection logic for both requests and responses
            is_http = False
            
            # Request detection
            if event.direction == 0:  # Send (request)
                is_http = (
                    any(method in payload[:20] for method in [b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"CONNECT "]) or
                    b"Content-Type: " in payload or b"Host: " in payload or b"User-Agent: " in payload
                )
            # Response detection
            else:  # Recv (response)
                is_http = (
                    b"HTTP/" in payload[:20] or
                    payload_str.strip().startswith("{") or payload_str.strip().startswith("[") or
                    b"Content-Type: " in payload
                )
                
            if is_http:
                process_name = event.comm.decode('utf-8', errors='ignore')
                pid = event.pid
                is_request = event.direction == 0
                src_addr = ip_to_str(event.saddr)
                dst_addr = ip_to_str(event.daddr)
                timestamp = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
                
                # Extract HTTP method, URL path, and host
                http_method = None
                url_path = None
                host = None
                
                if is_request:
                    http_method, url_path, host = extract_http_info(payload_str)
                else:
                    # For responses, get status code
                    status_match = re.match(r'HTTP/[\d.]+\s+(\d+)', payload_str)
                    if status_match:
                        http_method = f"RESPONSE-{status_match.group(1)}"
                
                # Create JSON output
                output = {
                    "processName": process_name,
                    "pid": pid,
                    "httpMethod": http_method if http_method else "UNKNOWN",
                    "urlPath": url_path if url_path else "",
                    "host": host if host else "",
                    "payload": payload_str,
                    "isRequest": is_request,
                    "sourceIp": src_addr,
                    "destinationIp": dst_addr,
                    "timestamp": timestamp
                }
                
                # Print as JSON
                print(json.dumps(output))
                
        except Exception as e:
            print(f"Error processing event: {e}")

def increase_memlock_rlimit():
    """Increase RLIMIT_MEMLOCK to allow BPF to create maps"""
    try:
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    except Exception as e:
        print(f"WARNING: Failed to increase RLIMIT_MEMLOCK: {e}")
        print("You might need to run with sudo or increase memlock limit in /etc/security/limits.conf")

def main():
    # Increase memory limits before loading eBPF program
    increase_memlock_rlimit()
    
    print("Loading eBPF program...")
    try:
        b = BPF(text=bpf_text)
    except Exception as e:
        print(f"Error loading BPF program: {e}")
        return
    
    # Attach to TCP functions
    try:
        b.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")
        b.attach_kprobe(event="tcp_recvmsg", fn_name="trace_tcp_recvmsg_entry")
        b.attach_kretprobe(event="tcp_recvmsg", fn_name="trace_tcp_recvmsg_ret")
    except Exception as e:
        print(f"Error attaching probes: {e}")
        return
    
    # Attach to ring buffer
    b["events"].open_ring_buffer(print_event)
    
    print("Starting HTTP traffic capture in JSON format...")
    print("Press Ctrl+C to exit")
    
    try:
        while True:
            b.ring_buffer_poll()
            time.sleep(0.1)  # Reduce CPU usage
    except KeyboardInterrupt:
        print("\nStopping HTTP traffic capture...")

if __name__ == "__main__":
    main()
