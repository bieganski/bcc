FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

# Normal update
RUN apt-get update -y

RUN apt-get -y install git pip file

WORKDIR /work

COPY ./gen_bindings.sh .
ADD ./bpftool ./bpftool

RUN ./gen_bindings.sh