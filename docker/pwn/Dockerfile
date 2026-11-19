FROM ctf-agent/analysis:0.2

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc-multilib \
        gdb-multiarch \
        libc6-dbg \
        qemu-user \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /challenge/work
CMD ["sleep", "infinity"]
