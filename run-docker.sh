#!/bin/sh
docker run \
  --expose 4444 \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp=unconfined \
  -it pwnenv-ubuntu-16.04
