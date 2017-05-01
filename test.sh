#!/bin/sh

docker build -f Dockerfile.nmap -t nmap .

MYIP=`ip route get 8.8.8.8 | awk '{print $NF; exit}'`
echo "ip address of my host is $MYIP"

echo "scan my host network with nmap from inside the container (assuming 24bit subnet)"
docker run --rm nmap $MYIP/24

echo "scan gateway ip for default network bridge"
GWIP=`docker network inspect bridge | jq .[0].IPAM.Config[0].Gateway | sed 's/"//g'`
docker run --rm nmap $GWIP

echo "scan gateway ip for newly created network bridge"
NWNAME="bridge-network-for-testing-firewall"
docker network create $NWNAME
GWIP=`docker network inspect $NWNAME | jq .[0].IPAM.Config[0].Gateway | sed 's/"//g'`
docker run --rm --net=$NWNAME nmap $GWIP
docker network rm $NWNAME
