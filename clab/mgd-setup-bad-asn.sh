#!/bin/bash

addr=`host -t A -4 clab-pop-oxpop | awk '{print $4}'`

~/src/maghemite/target/debug/mgadm -a $addr \
    bgp add-router 65547 1701 0.0.0.0:0

~/src/maghemite/target/debug/mgadm -a $addr \
    bgp add-neighbor 65547 transit 169.254.20.1 qsfp0 \
    --remote-asn 64502 \
    --min-ttl 255
