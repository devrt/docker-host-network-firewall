FROM bitnami/minideb:jessie

MAINTAINER Yosuke Matsusaka <yosuke.matsusaka@gmail.com>

ADD docker-host-network-firewall.py .
ADD requirements.txt .

RUN install_packages gcc libc-dev iptables-dev python-pip && pip install -r requirements.txt && apt-get --purge -y remove gcc libc-dev && apt-get --purge -y autoremove

CMD ["python2", "docker-host-network-firewall.py"]