# Run with --privileged
FROM gitlab/gitlab-runner:latest

RUN apt update \
    && apt --no-install-recommends -y install \
        qemu-system-x86 \
        python3 \
        python3-pip \
        ssh \
        ovmf \
    && apt clean

COPY . /root/mz-img-hack

RUN python3 -m pip install pexpect

# Mkosi stuff is written for mkosi 14.
RUN git clone --branch v14 https://github.com/systemd/mkosi.git
RUN python3 -m pip install ./mkosi/

ENTRYPOINT ["/usr/bin/dumb-init", "/entrypoint"]
CMD ["run"]
