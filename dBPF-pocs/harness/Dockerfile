FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
        clang llvm libelf-dev libbpf-dev linux-tools-generic \
        make gcc python3 python3-rich sudo kmod passwd keyutils \
        iproute2 iputils-ping procps util-linux tcpdump auditd libcap2-bin \
    && ln -sf $(ls /usr/lib/linux-tools/*/bpftool | head -1) /usr/local/bin/bpftool \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /w
