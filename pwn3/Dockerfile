FROM ubuntu:20.04

# insatll the goods
RUN apt update && apt install -y socat

# add users
RUN useradd -m -s /bin/bash pwn3

# add challenges
COPY src/libc.so.6 src/ld-2.31.so src/pwn3 src/flag /home/pwn3/
COPY src/init.sh /root/init.sh
RUN chmod 744 /root/init.sh

# perms
RUN chown -R root:pwn3 /home/pwn3 && chmod -R 750 /home/pwn3

EXPOSE 9003

ENTRYPOINT ["/root/init.sh"]
