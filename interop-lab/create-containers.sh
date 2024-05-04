#!/bin/bash

# create public cloud container
docker create \
        --privileged \
        --name=pubcloud \
        -h pubcloud \
        -e INTFTYPE=eth \
        -e ETBA=1 \
        -e SKIP_ZEROTOUCH_BARRIER_IN_SYSDBINIT=1 \
        -e CEOS=1 \
        -e EOS_PLATFORM=ceoslab \
        -e container=docker \
        -i \
        -t ceos:4.28.3M \
        /sbin/init \
        systemd.setenv=INTFTYPE=eth \
        systemd.setenv=ETBA=1 \
        systemd.setenv=SKIP_ZEROTOUCH_BARRIER_IN_SYSDBINIT=1 \
        systemd.setenv=CEOS=1 \
        systemd.setenv=EOS_PLATFORM=ceoslab \
        systemd.setenv=container=docker

# create cdn container
docker create \
	--name cdn \
    -h cdn \
    -t crpd:23.2R1.13

# create oxpop container
docker create \
    --name oxpop \
    -h oxpop \
    --entrypoint=/bin/bash \
    -v /opt/oxide:/opt/oxide \
    -t ubuntu:22.04
