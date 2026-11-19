FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/opt/ctf-venv/bin:${PATH}"

RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        binutils \
        binwalk \
        build-essential \
        ca-certificates \
        cmake \
        curl \
        dbus-x11 \
        ffmpeg \
        file \
        foremost \
        freerdp2-x11 \
        gdb \
        git \
        hashcat \
        imagemagick \
        john \
        john-data \
        jq \
        libffi-dev \
        libgmp-dev \
        libimage-exiftool-perl \
        libjpeg-dev \
        libmagic1 \
        libmcrypt-dev \
        libmhash-dev \
        libmpfr-dev \
        libpcap-dev \
        libssl-dev \
        ltrace \
        nmap \
        p7zip-full \
        pngcheck \
        poppler-utils \
        procps \
        python3 \
        python3-dev \
        python3-pip \
        python3-venv \
        ruby \
        ruby-dev \
        sleuthkit \
        socat \
        sox \
        sqlite3 \
        steghide \
        strace \
        tesseract-ocr \
        tesseract-ocr-chi-sim \
        tesseract-ocr-eng \
        tigervnc-viewer \
        tshark \
        unzip \
        wget \
        x11-utils \
        x11vnc \
        xauth \
        xclip \
        xdotool \
        xvfb \
        xxd \
        yara \
        zbar-tools \
        zip \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/ctf-venv \
    && /opt/ctf-venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel \
    && /opt/ctf-venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt

RUN gem install zsteg --no-document

RUN printf '%s\n' \
        '#!/bin/sh' \
        'mkdir -p /tmp/john-home' \
        'JOHN=/tmp/john-home HOME=/tmp/john-home exec /usr/sbin/john "$@"' \
        > /usr/local/bin/john \
    && printf '%s\n' \
        '#!/bin/sh' \
        'mkdir -p /tmp/hashcat-home' \
        'HOME=/tmp/hashcat-home exec /usr/bin/hashcat "$@"' \
        > /usr/local/bin/hashcat \
    && mkdir -p /root /tmp/john-home \
    && ln -sfn /tmp/john-home /root/.john \
    && chmod 0755 /usr/local/bin/john /usr/local/bin/hashcat

COPY third_party/stegseek-source.zip /tmp/stegseek-source.zip
RUN echo "3306e984bb9f1346332ad0e426e24bc697ba8061dc305c6347da8275e39ae33c  /tmp/stegseek-source.zip" \
        | sha256sum -c - \
    && mkdir -p /tmp/stegseek-source \
    && unzip -q /tmp/stegseek-source.zip -d /tmp/stegseek-source \
    && cmake -S /tmp/stegseek-source/stegseek-master -B /tmp/stegseek-source/build \
    && cmake --build /tmp/stegseek-source/build -j2 \
    && cmake --install /tmp/stegseek-source/build \
    && mkdir -p /usr/share/doc/stegseek \
    && cp /tmp/stegseek-source/stegseek-master/COPYING /usr/share/doc/stegseek/COPYING \
    && rm -rf /tmp/stegseek-source /tmp/stegseek-source.zip

RUN mkdir -p /challenge/input /challenge/artifacts /challenge/exploit /challenge/work
WORKDIR /challenge/work

CMD ["sleep", "infinity"]
