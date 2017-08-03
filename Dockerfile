#FROM docker as docker
FROM alpine

MAINTAINER Yosuke Matsusaka <yosuke.matsusaka@gmail.com>

RUN apk add --no-cache iptables

#COPY --from=docker /usr/local/bin/docker /bin/docker
ADD https://master.dockerproject.org/linux/x86_64/docker /bin/docker
RUN chmod 755 /bin/docker
ADD https://github.com/pts/staticpython/raw/master/release/python2.7-static /bin/python
RUN chmod 755 /bin/python
ADD docker-host-network-firewall.py .

CMD ["python", "docker-host-network-firewall.py"]