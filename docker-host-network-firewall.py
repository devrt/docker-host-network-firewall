#!/usr/bin/env python2

# protect your docker host network from possible trojan horse attack
# written by Yosuke Matsusaka <yosuke.matsusaka@gmail.com> 2017
#
# distributed under MIT license

import time
import subprocess
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
    created_rules = []

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
    return created_rules


def delete_rule_for_bridge(chain, bridge_name):
    rules = run_cmd('iptables -S {0}'.format(chain)).splitlines()
    for r in rules:
        e = shlex.split(r)
        if bridge_name in e:
            run_cmd('iptables -D {0} {1}'.format(chain, ' '.join(e[2:])))


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
run_cmd('iptables -D DOCKER-USER -j {0}'.format(c_fw_forward))
run_cmd('iptables -I DOCKER-USER -j {0}'.format(c_fw_forward))

bridge_name_for_id = {}

# create rule to protect local network
# for each network bridges
for id in get_existing_bridge_ids():
    print "enforce firewall rule for network " + id
    attrs = inspect_network(id)
    bridge_name = get_bridge_name(attrs)
    append_rule_for_bridge(c_fw, bridge_name, False)
    append_rule_for_bridge(c_fw_forward, bridge_name, True)

# monitor docker network events to update the rules
proc = subprocess.Popen(shlex.split('docker events --filter type=network --format "{{json .}}"'), stdout=subprocess.PIPE)
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
                except:
                    pass
