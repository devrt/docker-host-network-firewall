Protect your docker host network from possible trojan horse attack.

Background
----------

docker has a feature to isolate between networks created by docker itself, however, it won't isolate your host network.
You can confirm this fact by entering following commands.

Check your current iptables:

```
$ sudo iptables-save
```

Run nmap scans to see how your host network is visible from the container:

```
$ git clone https://github.com/devrt/docker-host-network-firewall.git
$ cd docker-host-network-firewall
$ ./test.sh
```

For those who pull and run third party docker container in your private network, you should be awared that the container may contain evil script to scan and steal your important informations on the network.

Now, docker-host-network-firewall is here to proctect you.

Enter following command to enforce the firewall:

```
$ docker run -ti --rm --cap-add=NET_ADMIN --net=host -v /var/run/docker.sock:/var/run/docker.sock devrt/host-network-firewall
```

Check your current iptables:

```
$ sudo iptables-save
```

Run nmap scans again to make sure it is protected.

Persist firewall protection
---------------------------

Once you have confirmed firewall protection, you can persist the protection by entering following command:

```
$ docker run --name host-network-firewall -d --restart=always --cap-add=NET_ADMIN --net=host -v /var/run/docker.sock:/var/run/docker.sock devrt/host-network-firewall
```

Notice
------

This firewall script only isolate between docker network and your host network.
Please note the containers linked inside the same docker network can communicate each other freely (so there is still an attack surface).


Written by
----------

Yosuke Matsusaka <yosuke.matsusaka@gmail.com>

Distributed under MIT license.
