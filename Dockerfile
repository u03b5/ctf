# pwn env quick setup
FROM ubuntu:16.04
EXPOSE 4444
RUN apt update && apt upgrade -y
RUN apt install -y gdb build-essential libc6-dbg wget curl
ENTRYPOINT bash

