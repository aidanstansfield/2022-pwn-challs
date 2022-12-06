FROM ubuntu:20.04

# insatll the goods
RUN apt update && apt install socat libc6-i386 -y

# add users
RUN useradd -m -s /bin/bash pwn-1

# add challenges
COPY src/pwn-1 src/flag /home/pwn-1/
COPY src/init.sh /root/init.sh
RUN chmod 744 /root/init.sh

# perms
RUN chown -R root:pwn-1 /home/pwn-1 && chmod -R 750 /home/pwn-1

EXPOSE 8999

ENTRYPOINT ["/root/init.sh"]
