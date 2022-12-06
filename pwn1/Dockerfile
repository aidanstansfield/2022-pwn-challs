FROM ubuntu:20.04

# insatll the goods
RUN apt update && apt install socat libc6-i386 -y

# add users
RUN useradd -m -s /bin/bash pwn1

# add challenges
COPY src/pwn1 src/flag /home/pwn1/
COPY src/init.sh /root/init.sh
RUN chmod 744 /root/init.sh

# perms
RUN chown -R root:pwn1 /home/pwn1 && chmod -R 750 /home/pwn1

EXPOSE 9001

ENTRYPOINT ["/root/init.sh"]
