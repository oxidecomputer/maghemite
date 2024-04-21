#!/bin/bash

set -x

addr=`host -t A -4 clab-pop-oxpop | awk '{print $4}'`

~/src/maghemite/target/debug/mgadm -a $addr \
    bgp ensure-router 65547 1701 0.0.0.0:0

# transit
~/src/maghemite/target/debug/mgadm -a $addr \
    bgp ensure-neighbor 65547 transit 169.254.10.1 qsfp0 \
    --remote-asn 64500 \
    --min-ttl 255 \
    --md5-auth-key hypermuffin \
    --hold-time 900 \
    --keepalive-time 300 \
    --communities 1287493 \
    --med 99

# cdn
~/src/maghemite/target/debug/mgadm -a $addr \
    bgp ensure-neighbor 65547 cdn 169.254.20.1 qsfp1 \
    --remote-asn 64501 \
    --min-ttl 255 \
    --md5-auth-key hypermuffin \
    --hold-time 900 \
    --keepalive-time 300 \
    --communities 3081893 \
    --med 99

# public cloud west
~/src/maghemite/target/debug/mgadm -a $addr \
    bgp ensure-neighbor 65547 pcwest 169.254.30.1 qsfp2 \
    --remote-asn 64502 \
    --min-ttl 255 \
    --md5-auth-key hypermuffin \
    --hold-time 900 \
    --keepalive-time 300 \
    --communities 8675309 \
    --med 99

# public cloud east
~/src/maghemite/target/debug/mgadm -a $addr \
    bgp ensure-neighbor 65547 pceast 169.254.40.1 qsfp3 \
    --remote-asn 64502 \
    --min-ttl 255 \
    --md5-auth-key hypermuffin \
    --hold-time 900 \
    --keepalive-time 300 \
    --communities 8675309 \
    --med 99

#~/src/maghemite/target/debug/mgadm -a $addr \
#	bgp load-shaper \
#	shaper.rhai 65547

~/src/maghemite/target/debug/mgadm -a $addr \
    bgp originate4 65547 \
    198.51.100.0/24 \
    192.168.12.0/24
