#!/usr/bin/env python3

import sys
import re
import networkx
import socket
import struct
import hashlib
from abc import ABC, abstractmethod
from time import sleep
from datetime import datetime
sys.path.append('cdn-alto/')
sys.path.append('alto-ale/')
from ipaddress import ip_address, IPv4Address

DEFAULT_ASN = 0
RR_BGP_0 = "50.50.50.1"
#RR_BGP = BGP_INFO['bgp']['ip']


class AltoModule(ABC):

    def __init__(self, mb):
        #self.props = {}
        self.pids = {}
        #self.topology = networkx.Graph()
        #self.cost_map = {}
        #self.router_ids = []
        self.ejes = {}
        self.vtag = 0
        self.mailbox = mb
        self.ts = {}

    ### Static Methods

    @staticmethod
    def discard_message_from_protocol_id(message, discard_protocols):
        """Discard message if protocol is inside discard_protocols list"""
        return message["protocol-id"] in discard_protocols

    @staticmethod
    def get_hex_id(ip):
        """Get hexadecimal value for certain IP
        :param: ip string"""
        return ''.join(['%02x' % int(w) for w in ip.split('.')])

    @staticmethod
    def check_is_hex(hex_value):
        try:
            int(hex_value, 16)
            return True
        except ValueError:
            return False

    @staticmethod
    def split_router_ids(router_id: str):
        """some router ids come without IP format. ie.e without dots in it
        convert these router_ids to IPs"""
        router_id = str(router_id)
        if '.' in router_id:
            return router_id
        router_groups = re.findall('...', router_id)
        no_zero_groups = []
        for group in router_groups:
            if group.startswith('00'):
                no_zero_groups.append(group[2:])
            elif group.startswith('0'):
                no_zero_groups.append(group[1:])
            else:
                no_zero_groups.append(group)
        return '.'.join(no_zero_groups)

    @staticmethod
    def check_if_router_id_is_hex(router_id):
        return router_id.isnumeric()

    @staticmethod
    def hex_to_ip(hex_ip):
        hex_ip = hex_ip.strip("0")
        addr_long = int(hex_ip, 16) & 0xFFFFFFFF
        struct.pack("<L", addr_long)
        return socket.inet_ntoa(struct.pack("<L", addr_long))

    @staticmethod
    def reverse_ip(reversed_ip):
        l = reversed_ip.split(".")
        return '.'.join(l[::-1])



    ### Auxiliar methods

    def ip_type(self, prefix):
        ip=prefix.split("/")[0]
        return "IPv4" if type(ip_address(ip)) is IPv4Address else "IPv6"

    def obtain_pid_sec(self, router, asn = 0):
        """Returns the hashed PID of the router passed as argument. 
            If the PID was already mapped, it uses a dictionary to access to it.
        """
        tsn = int(datetime.timestamp(datetime.now())*1000000)
        rid = self.get_hex_id(router) if not self.check_is_hex(router) else router
        if rid not in self.ts.keys():
            self.ts[rid] = tsn
        else:
            tsn = self.ts[rid]
        hash_r = hashlib.sha3_384((router + str(tsn)).encode())
        return ('pid%d:%s:%d' % (asn, hash_r.hexdigest()[:32], tsn))

    def obtain_pid(self, router, asn = 0):
        """Returns the hashed PID of the router passed as argument.
            If the PID was already mapped, it uses a dictionary to access to it.
        """
        rid = self.get_hex_id(router) if not self.check_is_hex(router) else router
        return ('pid%d:%s' % (asn, rid))

    def create_pid_name(self, lsa, descriptors, area_id):
        """Creates partition ID.
        with AS number + domain_id + area_id + hexadecimal router_id
        """
        routers_id = []
        desc = lsa[descriptors]
        for item in desc:
            if "router-id" in item:
                routers_id.append(item["router-id"])
        autonomous_systems = [item.get("autonomous-system") for item in desc]
        domain_ids = [item.get("domain-id", 0) for item in desc]
        for router_id, autonomous_system, domain_id in zip(routers_id, autonomous_systems, domain_ids):
            pid_name = 'pid%d:%s' % (autonomous_system, self.get_hex_id(router_id) if not self.check_is_hex(router_id) else router_id)
            #pid_name = self.obtain_pid(router_id)
            origin = (autonomous_system, domain_id, area_id, router_id)
            if pid_name not in self.props:
                self.props[pid_name] = []
            self.props[pid_name].append(origin)

    def get_router_id(self, value):
        if self.check_if_router_id_is_hex(value):
            return self.split_router_ids(value)
        elif "." in value:
            return value
        else:
            return self.reverse_ip(self.hex_to_ip(value))
    
    def get_info_from_node_descript_list(self, node_descriptors, key: str, rid=''):
        result = []
        for descriptor in node_descriptors:
            for key_d, value in descriptor.items():
                if key_d == key:
                    if key == "router-id":
                        result.append(self.get_router_id(value))
                        #print(value, key_d)
                    elif key == 'autonomous-system':
                        for des in node_descriptors:
                            for kd, val in des.items(): 
                                #print(kd,val)
                                if kd == "router-id":
                                    return value
        return result

    def parseo_yang(self, mensaje, tipo):
        return str(tipo) + 'json{"alto-tid":"1.0","time":' + str(datetime.timestamp(datetime.now())) + ',"host":"altoserver-alberto","' + str(tipo) + '":' + str(mensaje) + '},}'



    ### Topology generation and information recopilation functions

    def load_topology(self, lsa, igp_metric):
        if lsa.get('ls-nlri-type') == 'bgpls-link':
            # Link information
            src = self.get_info_from_node_descript_list(lsa['local-node-descriptors'], 'router-id')
            dst = self.get_info_from_node_descript_list(lsa['remote-node-descriptors'], 'router-id')
            for i, j in zip(src, dst):
                self.topology.add_edge(i, j, weight=igp_metric)
        if lsa.get('ls-nlri-type') == 'bgpls-prefix-v4':
            # ToDo verify if prefix info is needed and not already provided by node-descriptors
            # Node information. Groups origin with its prefixes
            origin = self.get_info_from_node_descript_list(lsa['node-descriptors'], "router-id")
            prefix = self.split_router_ids(lsa['ip-reach-prefix'])
            for item in origin:
                if item not in self.topology.nodes():
                    self.topology.add_node(item)
                if 'prefixes' not in self.topology.nodes[item]:
                    self.topology.nodes[item]['prefixes'] = []
                self.topology.nodes[item]['prefixes'].append(prefix)
        if lsa.get('ls-nlri-type') == "bgpls-node":
            # If ls-nlri-type is not present or is not of type bgpls-link or bgpls-prefix-v4
            # add node to topology if not present
            node_descriptors = self.get_info_from_node_descript_list(lsa['node-descriptors'], 'router-id')
            self.router_ids.append(node_descriptors)
            for node_descriptor in node_descriptors:
                if node_descriptor not in self.topology.nodes():
                    self.topology.add_node(node_descriptor)

    def load_pid_prop(self, lsa, ls_area_id):
        if 'node-descriptors' in lsa:
            self.create_pid_name(lsa, descriptors='node-descriptors', area_id=ls_area_id)
        if 'local-node-descriptors' in lsa:
            self.create_pid_name(lsa, descriptors='local-node-descriptors', area_id=ls_area_id)
        if 'remote-node-descriptors' in lsa:
            self.create_pid_name(lsa, descriptors='remote-node-descriptors', area_id=ls_area_id)

    def load_pids(self, ipv4db):
        # self.pids stores the result of networkmap
        for rr_bgp in [RR_BGP_0]:
            for prefix, data in ipv4db[rr_bgp]['ipv4'].items():
                pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.get_hex_id(data['next-hop']))
                #pid_name = self.obtain_pid(data['next-hop'])
                tipo=self.ip_type(prefix)
                if pid_name not in self.pids:
                    self.pids[pid_name] = {}
                if tipo not in self.pids[pid_name]:
                    self.pids[pid_name][tipo]=[]
                if prefix not in self.pids[pid_name][tipo]:
                    self.pids[pid_name][tipo].append(prefix)

    def compute_costmap(self):
        # shortest_paths is a dict by source and target that contains the shortest path length for
        # that source and destination
        shortest_paths = dict(networkx.shortest_paths.all_pairs_dijkstra_path_length(self.topology))
        for src, dest_pids in shortest_paths.items():
            src_pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.get_hex_id(src))
            #src_pid_name = self.obtain_pid(src)
            for dest_pid, weight in dest_pids.items():
                dst_pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.get_hex_id(dest_pid))
                #dst_pid_name = self.obtain_pid(dest_pid)
                if src_pid_name not in self.cost_map:
                    self.cost_map[src_pid_name] = {}
                self.cost_map[src_pid_name][dst_pid_name] = weight
    
    def return_info(self, src, tipo, costs, msn):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        meta = '{"source":'+str(src)+', "action":'+str(tipo)+', "costs":'+str(costs)+"}"
        msg = '{"meta":' + str(meta) +', "data":' + str(msn) + "}"
        msg = msg.replace("(", '"(')
        msg = msg.replace(")", ')"')
        print("Sending data to: " + str(self.mailbox))
        s.sendto(msg.encode(), self.mailbox)

    ### Manager function
    @abstractmethod
    def manage_topology_updates(self):
        pass
