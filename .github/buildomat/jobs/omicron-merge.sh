#!/bin/bash
#:
#: name = "omicron-merge"
#: variety = "basic"
#: target = "ubuntu-24.04"
#: skip_clone = true
# 
#: [dependencies.linux]
#: job = "linux"
#:
#: [dependencies.image]
#: job = "image"

# This doesn't actually test anything; it merely waits for the "linux" and
# "image" jobs to complete. Automation in the omicron repo keys off of this job
# to update a maghemite merge staging branch.

exit 0
