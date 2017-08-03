#!/usr/bin/env python2

# protect your docker host network from possible trojan horse attack
# written by Yosuke Matsusaka <yosuke.matsusaka@gmail.com> 2017
#
# distributed under MIT license

import time
import sys
import subprocess
import atexit
import shlex
import json


private_ips = [
    '192.168.0.0/16',
    '100.64.0.0/10',
    '172.16.0.0/12',
    '10.0.0.0/8'
]


def run_cmd(args):
    print "run cmd: " + args
    try:
        out = subprocess.check_output(shlex.split(args))
        if type(out) == bytes:
            out = out.decode('utf-8')
    except:
        out = -1
    return out


def get_existing_bridge_ids():
    return run_cmd('docker network ls --no-trunc --filter driver=bridge --format {{.ID}}').splitlines()


def inspect_network(id):
    return json.loads(run_cmd('docker network inspect {0}'.format(id)))[0]


def get_bridge_name(attrs):
    bridge_name = None
    try:
        bridge_name = attrs['Options']['com.docker.network.bridge.name']
    except KeyError:
        bridge_name = 'br-' + attrs['Id'][:12]
    return bridge_name


def append_rule_for_bridge(chain, bridge_name, is_forward=False):
    if is_forward:
        ioargs = '-i {0} ! -o {0}'.format(bridge_name)
    else:
        ioargs = '-i {0}'.format(bridge_name)
    # we want to allow the return packet for the connection from outside the container
    run_cmd('iptables -A {chain} {ioargs} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT'.format(chain=chain, ioargs=ioargs))
    run_cmd('iptables -A {chain} {ioargs} -m conntrack --ctstate INVALID -j DROP'.format(chain=chain, ioargs=ioargs))
    # drop all the packet directed to our private network
    for ip in private_ips:
        run_cmd('iptables -A {chain} -d {ip} {ioargs} -j DROP'.format(chain=chain, ip=ip, ioargs=ioargs))


def delete_rule_for_bridge(chain, bridge_name):
    rules = run_cmd('iptables -S {0}'.format(chain)).splitlines()
    for r in rules:
        e = shlex.split(r)
        if bridge_name in e:
            run_cmd('iptables -D {0} {1}'.format(chain, ' '.join(e[2:])))


def get_my_image_id_and_name():
    image_id_and_name = None
    with open('/proc/1/cpuset') as f:
        container_id = f.readline().replace('/docker/', '')
        image_id_and_name = run_cmd('docker inspect --format "{{.Image}} {{.Name}}" ' + container_id).strip().split()
    return image_id_and_name


def stop_agent(image_id_and_name):
    run_cmd('docker stop "{0[1]}-agent"'.format(image_id_and_name))


def respawn_agent_with_privilege():
    image_id_and_name = get_my_image_id_and_name()
    #atexit.register(stop_agent, image_id_and_name)  # should be stopped but not working (why?)
    proc = subprocess.Popen(shlex.split('docker run --name "{0[1]}-agent" -it --rm --cap-add=NET_ADMIN --net=host -v /var/run/docker.sock:/var/run/docker.sock {0[0]}'.format(image_id_and_name)), stdout=subprocess.PIPE)
    for l in iter(proc.stdout.readline, ''):
        sys.stdout.write(l)


# check if iptables is available with enough privilege
no_docker_user = False
out = run_cmd('iptables -S FORWARD')
if out == -1:
    print "it seems the container spawned without enough privilege, spawning agent container"
    respawn_agent_with_privilege()
    exit()
else:
    if '-A FORWARD -j DOCKER-USER' not in out.splitlines():
        print "DOCKER-USER chain not found (docker version < 17.06) using fallback"
        no_docker_user = True

# name of custom chains
c_fw = 'DOCKER-HOST-FW'
c_fw_forward = 'DOCKER-HOST-FW-F'

for c in [c_fw, c_fw_forward]:
    # create custom chain for protection
    run_cmd('iptables -N {0}'.format(c))
    # flush existing rule
    run_cmd('iptables -F {0}'.format(c))

# append custom chains to each parent
run_cmd('iptables -D INPUT -j {0}'.format(c_fw))
run_cmd('iptables -I INPUT -j {0}'.format(c_fw))
if no_docker_user:
    run_cmd('iptables -D FORWARD -j {0}'.format(c_fw_forward))
    run_cmd('iptables -I FORWARD -j {0}'.format(c_fw_forward))
else:
    run_cmd('iptables -D DOCKER-USER -j {0}'.format(c_fw_forward))
    run_cmd('iptables -I DOCKER-USER -j {0}'.format(c_fw_forward))

bridge_name_for_id = {}

# create rule to protect local area network for each network bridges
for id in get_existing_bridge_ids():
    print "enforce firewall rule for network " + id
    attrs = inspect_network(id)
    bridge_name = get_bridge_name(attrs)
    append_rule_for_bridge(c_fw, bridge_name, False)
    append_rule_for_bridge(c_fw_forward, bridge_name, True)

# monitor docker network events to update the rules
proc = subprocess.Popen(shlex.split('docker events --format "{{json .}}"'), stdout=subprocess.PIPE)
for l in iter(proc.stdout.readline, ''):
    e = json.loads(l)
    if 'Type' in e and e['Type'] == 'network':
        if 'Action' in e:
            action = e['Action']
            if action == 'create':
                id = e['Actor']['ID']
                print "detect creation of network " + id
                attrs = inspect_network(id)
                if attrs['Driver'] == 'bridge':
                    bridge_name = get_bridge_name(attrs)
                    append_rule_for_bridge(c_fw, bridge_name, False)
                    append_rule_for_bridge(c_fw_forward, bridge_name, True)
                    bridge_name_for_id[id] = bridge_name
            elif action == 'destroy':
                id = e['Actor']['ID']
                print "detect deletion of network " + id
                try:
                    bridge_name = bridge_name_for_id[id]
                    delete_rule_for_bridge(c_fw, bridge_name)
                    delete_rule_for_bridge(c_fw_forward, bridge_name)
                    del bridge_name_for_id[id]
                except:
                    pass
    if no_docker_user:
        # docker may occationally modify FORWARD rules order, so we check and reorder it
        out = run_cmd('iptables -S FORWARD').splitlines()
        v = out[0]
        if v == '-P FORWARD ACCEPT':
            v = out[1]
        if v != '-A FORWARD -j {0}'.format(c_fw_forward):
            run_cmd('iptables -D FORWARD -j {0}'.format(c_fw_forward))
            run_cmd('iptables -I FORWARD -j {0}'.format(c_fw_forward))
