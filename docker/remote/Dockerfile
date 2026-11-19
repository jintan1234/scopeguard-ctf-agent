FROM ctf-agent/analysis:0.2

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        freerdp2-x11 \
        scrot \
        tigervnc-viewer \
        x11-utils \
        x11vnc \
        xauth \
        xclip \
        xdotool \
        xvfb \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /challenge/work
CMD ["sleep", "infinity"]
