FROM python:2.7

MAINTAINER Yosuke Matsusaka <yosuke.matsusaka@gmail.com>

ADD docker-host-network-firewall.py .
ADD requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends iptables-dev && rm -rf /var/lib/apt/lists/*

RUN pip install -r requirements.txt

CMD ["python2", "docker-host-network-firewall.py"]