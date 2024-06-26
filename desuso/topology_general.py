#!/usr/bin/env python3

import os
import sys
import json
import re
import networkx
import socket
import struct
import hashlib

from time import sleep
from datetime import datetime
sys.path.append('cdn-alto/')
from bgp.manage_bgp_speaker import ManageBGPSpeaker
sys.path.append('alto-ale/')
from kafka_ale.kafka_api import AltoProducer

DEFAULT_ASN = 0
RR_BGP_0 = "50.50.50.1"
#RR_BGP = BGP_INFO['bgp']['ip']


class TopologyCreator:

    def __init__(self, exabgp_process, mode):
        self.exabgp_process = exabgp_process
        self.__props = {}
        self.__pids = {}
        self.topology = networkx.Graph()
        self.cost_map = {}
        self.router_ids = []
        # set path where to write result json files
        self.topology_writer = TopologyFileWriter('/root/')
        if mode:
            self.kafka_p = AltoProducer("localhost", "9092")
        #self.kafka_p = AltoProducer("localhost", "9093")
        self.ts = {}

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

    def obtain_pid(self, router):
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
        return ('pid%d:%s:%d' % (DEFAULT_ASN, hash_r.hexdigest()[:32], tsn))

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
            pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.get_hex_id(router_id) if not self.check_is_hex(router_id) else router_id)
            #pid_name = self.obtain_pid(router_id)
            origin = (autonomous_system, domain_id, area_id, router_id)
            if pid_name not in self.__props:
                self.__props[pid_name] = []
            self.__props[pid_name].append(origin)

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

    def _get_router_id_from_node_descript_list(self, node_descriptors, key: str):
        result = []
        for descriptor in node_descriptors:
            for key_d, value in descriptor.items():
                if key_d == key:
                    #print(value, key_d)
                    if self.check_if_router_id_is_hex(value):
                        result.append(self.split_router_ids(value))
                    elif "." in value:
                        result.append(value)
                    else:
                        result.append(self.reverse_ip(self.hex_to_ip(value)))
        return result

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

    def parseo_yang(self, mensaje, tipo):
        return str(tipo) + 'json{"alto-tid":"1.0","time":' + str(datetime.timestamp(datetime.now())) + ',"host":"altoserver-alberto","' + str(tipo) + '":' + str(mensaje) + '},}'

    def load_topology(self, lsa, igp_metric):
        if lsa.get('ls-nlri-type') == 'bgpls-link':
            # Link information
            src = self._get_router_id_from_node_descript_list(lsa['local-node-descriptors'], 'router-id')
            dst = self._get_router_id_from_node_descript_list(lsa['remote-node-descriptors'], 'router-id')
            for i, j in zip(src, dst):
                self.topology.add_edge(i, j, weight=igp_metric)
        if lsa.get('ls-nlri-type') == 'bgpls-prefix-v4':
            # ToDo verify if prefix info is needed and not already provided by node-descriptors
            # Node information. Groups origin with its prefixes
            origin = self._get_router_id_from_node_descript_list(lsa['node-descriptors'], "router-id")
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
            node_descriptors = self._get_router_id_from_node_descript_list(lsa['node-descriptors'], 'router-id')
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
        # self.__pids stores the result of networkmap
        for rr_bgp in [RR_BGP_0]:
            for prefix, data in ipv4db[rr_bgp]['ipv4'].items():
                pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.get_hex_id(data['next-hop']))
                #pid_name = self.obtain_pid(data['next-hop'])
                if pid_name not in self.__pids:
                    self.__pids[pid_name] = []
                if prefix not in self.__pids[pid_name]:
                    self.__pids[pid_name].append(prefix)

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
    
    def get_costs_map(self):
        return str(self.cost_map)

    def get_pids(self):
        return str(self.__pids)


    def shortest_path(self, a, b):
        try:
            return networkx.dijkstra_path(self.topology, a, b)
        except networkx.exception.NetworkXNoPath as e:
            return []
        except Exception as e:
            print(e)
            return (-1)

    def all_maps(self, topo, src, dst):
        '''
        Returns all the diferent paths between src and dest without any edge in common.
        The result is a list of paths (each path is represented as a char list, e.g. ['a', 'c', 'd'])
        Args:
            topo: Topology map
            src: node used as source
            dst: node used as destination
        '''
        map_aux = networkx.Graph(topo)
        all_paths = []

        sh_path = networkx.dijkstra_path(map_aux, src, dst)
        while sh_path != []:
            cost = 0
            nodo_s = sh_path[0]
            for nodo_d in sh_path[1:]:
                map_aux.remove_edge(nodo_s, nodo_d)
                nodo_s = nodo_d
                cost = cost + 1

            all_paths.append({'path':sh_path, 'cost':cost})
            try:
                sh_path = networkx.dijkstra_path(map_aux, src, dst)
            except networkx.exception.NetworkXNoPath as e:
                sh_path = []
        return all_paths

    def manage_bgp_speaker_updates(self, mode):
        """
        Reads stdout of process exabgp. It reads line by line
        Decoded update messages from exabgp are used to build the netwokmap and costmap
        :return:
        """
        pids_to_load = {RR_BGP_0: {'ipv4': {}}}
        while True:
            line = self.exabgp_process.stdout.readline().strip()
            if b'decoded UPDATE' in line and b'json' in line:
                #print(line)
                decode_line = json.loads(line.split(b'json')[1])
                neighbor_ip_address = decode_line['neighbor']['address']['peer']
                update_msg = decode_line['neighbor']['message']['update']
                if 'announce' in update_msg:
                    is_bgp_ls = update_msg['announce'].get('bgp-ls bgp-ls')
                    is_bgp = update_msg['announce'].get('ipv4 unicast')
                    if 'attribute' in update_msg:
                        ls_area_id = update_msg['attribute'].get('bgp-ls', {}).get('area-id', 0)
                        igp_metric = update_msg['attribute'].get('bgp-ls', {}).get("igp-metric", 1)
                        if is_bgp_ls:
                            for next_hop_address, nlri in is_bgp_ls.items():
                                for prefix in nlri:
                                    if self.discard_message_from_protocol_id(prefix, [4, 5]):
                                        continue
                                    self.load_topology(prefix, igp_metric)
                                    self.load_pid_prop(prefix, ls_area_id)
                        elif is_bgp:
                            for next_hop, prefix in is_bgp.items():
                                for nlri in prefix:
                                    pids_to_load[neighbor_ip_address]['ipv4'][nlri['nlri']] = {'next-hop': next_hop}
                                    self.load_pids(pids_to_load)

                elif 'withdraw' in update_msg and 'bgp-ls bgp-ls' in update_msg['withdraw']:
                    for route in update_msg['withdraw']['bgp-ls bgp-ls']:
                        u=0;v=0
                        for field, values in route.items():
                            if field == "local-node-descriptors":
                                for n in values:
                                    for i, j in n.items():
                                        if i == "router-id":
                                            u=j
                            elif field == "remote-node-descriptors":
                                for n in values:
                                    for i, j in n.items():
                                        if i == "router-id":
                                            v=j
                            if u != 0 and v != 0:
                                try:
                                    self.topology.remove_edge(self.split_router_ids(u), self.split_router_ids(v))
                                except:
                                    print("Eje ya removido.")
                
                self.compute_costmap()
                self.topology_writer.write_same_ips(self.router_ids)
                self.topology_writer.write_pid_file(self.__pids)
                self.topology_writer.write_cost_map(self.cost_map)

            if bool(self.cost_map) :
                if mode:
                    self.kafka_p.envio_alto('alto-costes', self.cost_map, 0)
                

class TopologyFileWriter:

    def __init__(self, output_path):
        self.output_path = output_path
        self.pid_file = 'pid_file.json'
        self.cost_map_file = 'cost_map.json'
        self.same_node_ips = "router_ids.json"

    def write_file(self, file_name, content_to_write):
        """Writes file_name in output_file"""
        full_path = os.path.join(self.output_path, file_name)
        with open(full_path, 'w') as out_file:
            json.dump(content_to_write, out_file, indent=4)

    def write_pid_file(self, content):
        self.write_file(self.pid_file, content)

    def write_cost_map(self, content):
        self.write_file(self.cost_map_file, content)

    def write_same_ips(self, content):
        self.write_file(self.same_node_ips, content)


if __name__ == '__main__':
    speaker_bgp = ManageBGPSpeaker()
    exabgp_process = speaker_bgp.check_tcp_connection()
    
    topology_creator = TopologyCreator(exabgp_process,1)
    topology_creator.manage_bgp_speaker_updates(1)
