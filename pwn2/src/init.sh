#!/bin/bash

# Start the process
cd /home/pwn2 && /usr/bin/socat -dd TCP4-LISTEN:9002,fork,reuseaddr,su=pwn2 EXEC:/home/pwn2/pwn2,pty,echo=0,raw,iexten=0 &
status=$?
if [ $status -ne 0 ]; then
  echo "Failed to start pwn2: $status"
  exit $status
fi

sleep infinity