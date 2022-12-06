FROM ubuntu:20.04

# insatll the goods
RUN apt update && apt install -y socat 

# add users
RUN useradd -m -s /bin/bash pwn2

# add challenges
COPY src/libc.so.6 src/ld-2.31.so src/pwn2 src/flag /home/pwn2/
COPY src/init.sh /root/init.sh
RUN chmod 744 /root/init.sh

# perms
RUN chown -R root:pwn2 /home/pwn2 && chmod -R 750 /home/pwn2

EXPOSE 9002

ENTRYPOINT ["/root/init.sh"]
