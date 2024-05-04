#!/bin/bash

curl -s 'http://admin:NokiaSrl1!@clab-pop-transit/jsonrpc' -d @- <<EOF | jq
{
    "jsonrpc": "2.0",
    "id": 0,
    "method": "get",
    "params": {
        "commands": [
            {
                "path": "/network-instance[name=default]/bgp-rib/afi-safi[afi-safi-name=ipv4-unicast]",
                "datastore": "state"
            }
        ]
    }
}
EOF
