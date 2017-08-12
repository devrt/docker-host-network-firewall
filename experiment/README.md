Experimental docker image to learn possibility of trojan horse attack using docker container


Dislaimer
---------

For experimental purpose only, do not use this on any target which you do not have permission to do so.


To run the experiment
---------------------

Attacker side: Compile the image and start the remote control server

```
$ docker build -f Dockerfile.victim -t very-useful-app .
$ ./server.sh
```

In this specific experiment, we run our server on 127.0.0.1:4545. But in real case, the attacker will use global IP of their VPS server.

Attacker will push the "very-useful-app" image to docker registry and wait for the victim to run the image.

Victim side (on the different terminal): Run the docker image

```
$ docker run -it --net=host very-useful-app
```

In this specific experiment, we use --net=host option to connect to the server running at 127.0.0.1. But in real case, when the attacker use their global IP, we can omit this option.

Once the container start running, you can remote control victim's docker container from your server.
You can install any utility (e.g. nmap) to scan victim's network to steal any credentials as well.

Please get noticed that this experiment is conducted only with standard socat command, so it is hard to detect by the security scanner.


How to protect our network from such attack?
--------------------------------------------

Use docker-host-network-firewall.

Completely disable network traffic from docker container to global IP is also useful to prevent such remote control attack.
