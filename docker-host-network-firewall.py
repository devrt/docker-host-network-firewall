#!/usr/bin/env python2

# protect your docker host network from possible trojan horse attack
# written by Yosuke Matsusaka <yosuke.matsusaka@gmail.com> 2017
#
# distributed under MIT license

import time
import docker
import iptc


private_ips = [
    '192.168.0.0/16',
    '100.64.0.0/10',
    '172.16.0.0/12',
    '10.0.0.0/8'
]


def get_or_create_chain(table, chain_name):
    if table.is_chain(chain_name):
        return iptc.Chain(table, chain_name)
    return table.create_chain(chain_name)


def bring_chain_to_top(chain, chain2):
    if len(chain.rules) > 0 and chain.rules[0].target.name == chain2.name:
        return
    for r in chain.rules:
        if r.target.name == chain2.name:
            chain.delete_rule(r)
    rule = iptc.Rule()
    rule.target = iptc.Target(rule, chain2.name)
    chain.insert_rule(rule)


def get_bridge_name(n):
    bridge_name = None
    try:
        bridge_name = n.attrs['Options']['com.docker.network.bridge.name']
    except KeyError:
        bridge_name = 'br-' + n.id[:12]
    return bridge_name


def append_rule_for_bridge(chain, bridge_name, is_forward=False):
    created_rules = []
    
    # we want to allow the return packet for the connection from outside the container
    rule = iptc.Rule()
    rule.in_interface = bridge_name
    if is_forward:
        rule.out_interface = '!' + bridge_name
    match = iptc.Match(rule, 'conntrack')
    match.ctstate = 'RELATED,ESTABLISHED'
    rule.add_match(match)
    rule.target = iptc.Target(rule, 'ACCEPT')
    chain.append_rule(rule)
    created_rules.append(rule)
    
    rule = iptc.Rule()
    rule.in_interface = bridge_name
    if is_forward:
        rule.out_interface = '!' + bridge_name
    match = iptc.Match(rule, 'conntrack')
    match.ctstate = 'INVALID'
    rule.add_match(match)
    rule.target = iptc.Target(rule, 'DROP')
    chain.append_rule(rule)
    created_rules.append(rule)
    
    # drop all the packet directed to our private network
    for ip in private_ips:
        rule = iptc.Rule()
        rule.in_interface = bridge_name
        if is_forward:
            rule.out_interface = '!' + bridge_name
        rule.dst = ip
        rule.target = iptc.Target(rule, 'DROP')
        chain.append_rule(rule)
        created_rules.append(rule)
    return created_rules


d = docker.from_env()

table = iptc.Table(iptc.Table.FILTER)
c_input = iptc.Chain(table, 'INPUT')
c_forward = iptc.Chain(table, 'FORWARD')

# create custom chains for protection
c_fw = get_or_create_chain(table, 'DOCKER-HOST-FW')
c_fw_forward = get_or_create_chain(table, 'DOCKER-HOST-FW-F')

c_fw.flush()
c_fw_forward.flush()

# created rules
rules_for_nw = {}
forward_rules_for_nw = {}

# firewall rules should always stay on top
bring_chain_to_top(c_input, c_fw)
bring_chain_to_top(c_forward, c_fw_forward)

# create rule to protect local network
# for each network bridges
for n in d.networks.list():
    if n.attrs['Driver'] == 'bridge':
        print "enforce firewall rule for network " + n.id
        bridge_name = get_bridge_name(n)
        rules_for_nw[n.id] = append_rule_for_bridge(c_fw, bridge_name, False)
        forward_rules_for_nw[n.id] = append_rule_for_bridge(c_fw_forward, bridge_name, True)

failed_rules = []
# monitor docker network events to update the rules
for e in d.events(decode=True):
    if 'Type' in e and e['Type'] == 'network':
        if 'Action' in e:
            action = e['Action']
            if action == 'create':
                id = e['Actor']['ID']
                print "detect creation of network " + id
                n = d.networks.get(id)
                if n.attrs['Driver'] == 'bridge':
                    bridge_name = get_bridge_name(n)
                    rules_for_nw[id] = append_rule_for_bridge(c_fw, bridge_name, False)
                    forward_rules_for_nw[id] = append_rule_for_bridge(c_fw_forward, bridge_name, True)
            elif action == 'destroy':
                id = e['Actor']['ID']
                print "detect deletion of network " + id
                if id in rules_for_nw:
                    for r in reversed(rules_for_nw[id]):
                        try:
                            c_fw.delete_rule(r)
                        except iptc.IPTCError:
                            print "error occoured when deleting rule (retry later)"
                            failed_rules.append([c_fw, r])
                if id in forward_rules_for_nw:
                    for r in reversed(forward_rules_for_nw[id]):
                        try:
                            c_fw_forward.delete_rule(r)
                        except iptc.IPTCError:
                            print "error occoured when deleting rule (retry later)"
                            failed_rules.append([c_fw_forward, r])

        # retry if there is any failed rule deletion
        failed_again = []
        for f in failed_rules:
            try:
                f[0].delete_rule(f[1])
            except iptc.IPTCError:
                print "error occoured when deleting rule"
                failed_again.append(f)
        failed_rules = failed_again

        # firewall rules should always stay on top (docker sometimes break this order on network reconfiguration)
        bring_chain_to_top(c_input, c_fw)
        bring_chain_to_top(c_forward, c_fw_forward)
