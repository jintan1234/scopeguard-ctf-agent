FROM sagemath/sagemath@sha256:310dfe23fc786f3a5a06a7b0387c60201ec79b32c0db941b7624505ee5edb565

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        jq \
        python3 \
    && rm -rf /var/lib/apt/lists/*

RUN if [ -d /home/sage ]; then chmod -R a+rX /home/sage; fi
RUN mkdir -p /challenge/input /challenge/artifacts /challenge/exploit /challenge/work
WORKDIR /challenge/work
ENTRYPOINT []
CMD ["sleep", "infinity"]
