FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update -y
RUN apt-get install -y git pip file libelf-dev clang llvm libc6-dev pkg-config linux-libc-dev linux-headers-generic

WORKDIR /work

RUN git clone https://github.com/bieganski/libbpf
RUN cd libbpf/src && make -B && ldd libbpf.so

RUN ls
RUN git clone https://github.com/bieganski/bcc
RUN cd bcc && git submodule update --init --recursive
RUN cd bcc/libbpf-tools && rm -f ./libbpf.so* && ln -s /work/libbpf/src/libbpf.so.1.4.0 libbpf.so.1 && ln -s libbpf.so.1 libbpf.so && make -B -j20
RUN pip3 install --upgrade pip
RUN pip3 install astor
RUN pip3 install git+https://github.com/bieganski/ctypesgen
RUN cd bcc/libbpf-tools && ./gen_bindings.sh --libbpf-root /work/libbpf
