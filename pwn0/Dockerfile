FROM ubuntu:20.04

# insatll the goods
RUN apt update && apt install socat libc6-i386 -y

# add users
RUN useradd -m -s /bin/bash pwn0

# add challenges
COPY src/pwn0 src/flag /home/pwn0/
COPY src/init.sh /root/init.sh
RUN chmod 744 /root/init.sh

# perms
RUN chown -R root:pwn0 /home/pwn0 && chmod -R 750 /home/pwn0

EXPOSE 9000

ENTRYPOINT ["/root/init.sh"]
