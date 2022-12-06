#!/bin/bash

# Start the process
cd /home/pwn-1 && /usr/bin/socat -dd TCP4-LISTEN:8999,fork,reuseaddr,su=pwn-1 EXEC:/home/pwn-1/pwn-1,pty,echo=0,raw,iexten=0 &
status=$?
if [ $status -ne 0 ]; then
  echo "Failed to start pwn-1: $status"
  exit $status
fi

sleep infinity