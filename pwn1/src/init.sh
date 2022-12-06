#!/bin/bash

# Start the process
cd /home/pwn1 && /usr/bin/socat -dd TCP4-LISTEN:9001,fork,reuseaddr,su=pwn1 EXEC:/home/pwn1/pwn1,pty,echo=0,raw,iexten=0 &
status=$?
if [ $status -ne 0 ]; then
  echo "Failed to start pwn1: $status"
  exit $status
fi

sleep infinity