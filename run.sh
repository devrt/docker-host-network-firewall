#!/bin/sh

docker run -ti --rm --cap-add=NET_ADMIN --net=host -v /var/run/docker.sock:/var/run/docker.sock devrt/host-network-firewall
