#!/bin/bash

addr=`host -t A -4 clab-pop-oxpop | awk '{print $4}'`

~/src/maghemite/target/debug/mgadm -a $addr \
    bgp add-router 64501 1701 0.0.0.0:0

~/src/maghemite/target/debug/mgadm -a $addr \
    bgp add-neighbor 64501 transit 169.254.20.1 qsfp0 \
    --remote-asn 64501 \
    --min-ttl 255 \
    --md5-auth-key hypermuffin \
    --hold-time 900 \
    --keepalive-time 300 \
    --communities 3081893 \
    --local-pref 47 \
    --med 99
