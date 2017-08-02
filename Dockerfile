FROM docker as docker
FROM busybox

MAINTAINER Yosuke Matsusaka <yosuke.matsusaka@gmail.com>

COPY --from=docker /usr/local/bin/docker /bin/docker
ADD https://github.com/pts/staticpython/raw/master/release/python2.7-static /bin/python
RUN chmod 755 /bin/python
ADD docker-host-network-firewall.py .

CMD ["python", "docker-host-network-firewall.py"]