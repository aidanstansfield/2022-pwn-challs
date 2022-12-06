#!/bin/bash

# Start the process
cd /home/pwn0 && /usr/bin/socat -dd TCP4-LISTEN:9000,fork,reuseaddr,su=pwn0 EXEC:/home/pwn0/pwn0,pty,echo=0,raw,iexten=0 &
status=$?
if [ $status -ne 0 ]; then
  echo "Failed to start pwn0: $status"
  exit $status
fi

sleep infinity