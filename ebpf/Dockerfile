FROM --platform=linux/arm64 ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    linux-headers-generic \
    linux-libc-dev \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ... (rest of your Dockerfile)

WORKDIR /app

# Create symlinks for ARM64 architecture headers
RUN mkdir -p /usr/include/asm && \
    ln -s /usr/include/aarch64-linux-gnu/asm/bitsperlong.h /usr/include/asm/bitsperlong.h

COPY . .

RUN go get github.com/cilium/ebpf@latest && \
    go mod tidy && \
    go generate && \
    go build -o packet_capture

CMD ["./packet_capture"]