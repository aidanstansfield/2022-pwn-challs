#!/bin/bash

# Start the process
cd /home/pwn3 && /usr/bin/socat -dd TCP4-LISTEN:9003,fork,reuseaddr,su=pwn3 EXEC:/home/pwn3/pwn3,pty,echo=0,raw,iexten=0 &
status=$?
if [ $status -ne 0 ]; then
  echo "Failed to start pwn3: $status"
  exit $status
fi

sleep infinity