#!/bin/sh

docker run --name host-network-firewall -d --restart=always --cap-add=NET_ADMIN --net=host -v /var/run/docker.sock:/var/run/docker.sock devrt/host-network-firewall
