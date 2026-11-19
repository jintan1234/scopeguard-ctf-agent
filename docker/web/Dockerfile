FROM ctf-agent/analysis:0.2

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ffuf \
        gobuster \
        krb5-user \
        libkrb5-dev \
        nikto \
        smbclient \
        sqlmap \
        whatweb \
    && rm -rf /var/lib/apt/lists/*

RUN /opt/ctf-venv/bin/pip install --no-cache-dir \
        mitmproxy \
        impacket

RUN gem install wpscan --no-document

WORKDIR /challenge/work
CMD ["sleep", "infinity"]
