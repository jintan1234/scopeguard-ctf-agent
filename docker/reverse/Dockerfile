FROM ctf-agent/analysis:0.2

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        apktool \
        openjdk-21-jdk-headless \
        radare2 \
    && rm -rf /var/lib/apt/lists/*

RUN printf '%s\n' \
        '#!/bin/sh' \
        'mkdir -p /tmp/apktool-home' \
        'HOME=/tmp/apktool-home exec /usr/bin/apktool "$@"' \
        > /usr/local/bin/apktool \
    && chmod 0755 /usr/local/bin/apktool

WORKDIR /challenge/work
CMD ["sleep", "infinity"]
