#!/bin/bash

addr=`host -t A -4 clab-pop-oxpop | awk '{print $4}'`
export ADDRESS=$addr
export MAGHEMITE_ENDPOINT=$addr
