#!/bin/bash

apt update -y
apt install -y iproute2

ip addr add 169.254.10.2/30 dev eth1
ip addr add 169.254.20.2/30 dev eth2
ip addr add 169.254.30.2/30 dev eth3
ip addr add 169.254.40.2/30 dev eth4

/opt/oxide/mgd run
