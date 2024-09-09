FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

# Normal update
RUN apt-get update -y

RUN apt-get -y install git pip file libelf-dev

WORKDIR /work

COPY ./libbpf.so.1.4.0 .
COPY ./libbpf.so.1 .
COPY ./libbpf.so .
COPY ./gen_bindings.sh .
ADD ./bpftool ./bpftool

RUN ./gen_bindings.sh