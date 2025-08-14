from bcc import BPF
from bcc.utils import printb

# load BPF program
b = BPF(src_file="http_capture.c")

# Callback function to process events
def process_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"PID: {event.pid}, Port: {event.port}, Msg Size: {event.msg_size}, IOV Len: {event.iov_len}, IOV Base: 0x{event.iov_base:x}")
    print("Data (first 256 bytes):")
    print(event.data.decode('utf-8', 'ignore'))
    print("Hex:")
    print(event.data.hex())
    print("---")
    
    # Search for the payload
    full_data = event.data.decode('utf-8', 'ignore')
    headers_end = full_data.find('\r\n\r\n')
    if headers_end != -1:
        payload = full_data[headers_end+4:]
        print("Payload:")
        print(payload)
    else:
        print("Payload not found in captured data")

# Attach the event to the perf buffer
b["events"].open_perf_buffer(process_event)

print("Tracing... Hit Ctrl-C to end.")

# Poll the perf buffer
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("Exiting...")

# Clean up
b.cleanup()