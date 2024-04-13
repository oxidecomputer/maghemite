#!/bin/bash

curl -s 'http://admin:NokiaSrl1!@clab-pop-transit/jsonrpc' -d @- <<EOF | jq
{
    "jsonrpc": "2.0",
    "id": 0,
    "method": "get",
    "params": {
        "commands": [
            {
                "path": "/network-instance[name=default]/protocols/bgp/neighbor[peer-address=169.254.20.2]/afi-safi[afi-safi-name=ipv4-unicast]/received-routes",
                "datastore": "state"
            }
        ]
    }
}
EOF
