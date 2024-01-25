#!/usr/bin/env python3

import os
import sys
import json
import re
import networkx
import json
import hashlib

from datetime import datetime
sys.path.append('cdn-alto/')
from bgp.manage_bgp_speaker import ManageBGPSpeaker
sys.path.append('alto-ale/')
from kafka_ale.kafka_api import AltoProducer

DEFAULT_ASN = 0
RR_BGP_0 = "50.50.50.1"
#RR_BGP = BGP_INFO['bgp']['ip']


class TopologyCreator:

    def __init__(self, exabgp_process):
        self.exabgp_process = exabgp_process
        self.__props = {}
        self.__pids = {}
        self.topology = networkx.MultiGraph()
        self.cost_map = {}
        # set path where to write result json files
        self.topology_writer = TopologyFileWriter('/root/')
        self.kafka_p = AltoProducer("localhost", "9092")
        #self.kafka_p = AltoProducer("localhost", "9093")
        self.ts = {}

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
            #pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.get_hex_id(router_id) if not self.check_is_hex(router_id) else router_id)
            tsn = int(datetime.timestamp(datetime.now())*1000000)
            #pid_name = 'pid%d:%s:%d' % (DEFAULT_ASN, str(hash(router_id + str(ts))), ts)
            rid = self.get_hex_id(router_id) if not self.check_is_hex(router_id) else router_id
            if rid not in self.ts.keys():
                self.ts[rid] = tsn
            else:
                tsn = self.ts[rid]
            hash_r = hashlib.sha3_384((router_id + str(tsn)).encode())
            pid_name = 'pid%d:%s:%d' % (DEFAULT_ASN, hash_r.hexdigest()[:32], tsn)
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
        return [self.split_router_ids(descriptor.get(key)) for descriptor in node_descriptors]

    def load_topology(self, lsa):
        if lsa.get('ls-nlri-type') == 'bgpls-link':
            # Link information
            src = self._get_router_id_from_node_descript_list(lsa['local-node-descriptors'], 'router-id')
            dst = self._get_router_id_from_node_descript_list(lsa['remote-node-descriptors'], 'router-id')
            for i, j in zip(src, dst):
                self.topology.add_edge(i, j)
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
        if 'node-descriptors' in lsa:
            # If ls-nlri-type is not present or is not of type bgpls-link or bgpls-prefix-v4
            # add node to topology if not present
            node_descriptors = self._get_router_id_from_node_descript_list(lsa['node-descriptors'], 'router-id')
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
    
    '''
    Modificación 1.1:
        En vez de utilizar los PIDs directamente se realiza un hash sha3 del router_id (su IP) con un salt (El ASN)
    Modificación 1.2:
        Utilizamos un timestamp con precisión de microsegundos para "sazonar" el hash.
        Para mantener una coherencia con las veces previas se realizará un mapeado IP:timestamp la primera vez que se mapee el nodo.
        Si un nodo se cae no tendrá problemas de duplicidad al no depender esto del grafo.
    '''
    def load_pids(self, ipv4db):
        # self.__pids stores the result of networkmap
        for rr_bgp in [RR_BGP_0]:
            for prefix, data in ipv4db[rr_bgp]['ipv4'].items():
                #pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.get_hex_id(data['next-hop']))
                if self.get_hex_id(data['next-hop']) not in self.ts.keys():
                    tsn = int(datetime.timestamp(datetime.now())*1000000)
                    self.ts[self.get_hex_id(data['next-hop'])] = tsn
                else:
                    tsn = self.ts[self.get_hex_id(data['next-hop'])]
                hash_r = hashlib.sha3_384((data['next-hop'] + str(tsn)).encode())
                pid_name = 'pid%d:%s:%d' % (DEFAULT_ASN, hash_r.hexdigest()[:32], tsn)
                if pid_name not in self.__pids:
                    self.__pids[pid_name] = []
                if prefix not in self.__pids[pid_name]:
                    self.__pids[pid_name].append(prefix)

    def compute_costmap(self):
        # shortest_paths is a dict by source and target that contains the shortest path length for
        # that source and destination
        shortest_paths = dict(networkx.shortest_paths.all_pairs_dijkstra_path_length(self.topology))
        for src in self.__pids:
            sp = self.__props.get(src, [(0, None)])[0][-1]
            self.cost_map[src] = dict()
            for dst in self.__pids:
                dp = self.__props.get(dst, [(0, None)])[0][-1]
                if sp is not None and dp is not None:
                    self.cost_map[src][dst] = shortest_paths.get(sp, {}).get(dp, 64)

    def manage_bgp_speaker_updates(self):
        """
        Reads stdout of process exabgp. It reads line by line
        Decoded update messages from exabgp are used to build the netwokmap and costmap
        :return:
        """
        pids_to_load = {RR_BGP_0: {'ipv4': {}}} 
        mapa_aux={}
        while True: 
            line = self.exabgp_process.stdout.readline().strip()
            if b'decoded UPDATE' in line and b'json' in line:
                #print(f"LINEA!!!! {line.split(b'json')}")
                decode_line = json.loads(line.split(b'json')[1])
                neighbor_ip_address = decode_line['neighbor']['address']['peer']
                update_msg = decode_line['neighbor']['message']['update']
                if 'announce' in update_msg:
                    is_bgp_ls = update_msg['announce'].get('bgp-ls bgp-ls')
                    is_bgp = update_msg['announce'].get('ipv4 unicast')
                    if 'attribute' in update_msg:
                        #Aquí tenemos que ver cómo incluir los mapas multicostes.
                        ls_area_id = update_msg['attribute'].get('bgp-ls', {}).get('area-id', 0)
                        if is_bgp_ls:
                            for next_hop_address, nlri in is_bgp_ls.items():
                                for prefix in nlri:
                                    self.load_topology(prefix)
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
                self.topology_writer.write_pid_file(self.__pids)
                self.topology_writer.write_cost_map(self.cost_map)
            
            if bool(self.cost_map) :
                self.kafka_p.envio_alto('alto-costes', self.cost_map)
            
            #icode = self.kafka_p.envio_alto_archivo('alto-costes', self.topology_writer.output_path, "cost_map.json")
            #if not icode :
            #    print("No se ha podido realizar la escritura")
            #else:
            #    print("Escritura correcta")
            #self.kafka_p.envio_alto("alto-costes", self.cost_map)
            #self.kafka_p.envio_alto("alto-pids", self.__pids)
    def shortest_path(graph):
        return dict(networkx.dijkstra_path(graph))
    
    def all_maps(topo, src, dst):
        '''
        Returns all the diferent paths between src and dest without any edge in common.
        The result is a list of paths (each path is represented as a char list, e.g. ['a', 'c', 'd'])
        Args: 
            topo: Topology map
            src: node used as source
            dst: node used as destination
        '''
        map_aux = networkx.MultiGraph(topo)
        all_paths = []
        
        sh_path = networkx.dijkstra_path(map_aux, src, dst)
        while sh_path != []:
        
            nodo_s = sh_path[0]
            for nodo_d in sh_path[1:]:
                map_aux.remove_edge(nodo_s, nodo_d)
                nodo_s = nodo_d
            
            all_paths.append([sh_path])
            sh_path = networkx.dijkstra_path(map_aux, src, dst)
        
        return all_paths


'''
Next to do:
    - Code that uses other metrics than nº of jumps (ponderated edges or something like that)
    - Evaluate the functionality once the environment is working
'''



class TopologyFileWriter:

    def __init__(self, output_path):
        self.output_path = output_path
        self.pid_file = 'pid_file.json'
        self.cost_map_file = 'cost_map.json'

    def write_file(self, file_name, content_to_write):
        """Writes file_name in output_file"""
        full_path = os.path.join(self.output_path, file_name)
        with open(full_path, 'w') as out_file:
            json.dump(content_to_write, out_file, indent=4)

    def write_pid_file(self, content):
        self.write_file(self.pid_file, content)

    def write_cost_map(self, content):
        self.write_file(self.cost_map_file, content)


if __name__ == '__main__':
    
    speaker_bgp = ManageBGPSpeaker()
    exabgp_process = speaker_bgp.check_tcp_connection()

    topology_creator = TopologyCreator(exabgp_process)
    topology_creator.manage_bgp_speaker_updates()







"""
                                    #print("N:\t", n)
                                    for i, j in n.items():
                                        if i == "router-id":
                                            print("IDs:\t", self.split_router_ids(j))
                                            #try:
                                                #self.topology.remove_node(self.split_router_ids(j))
                                            #except:
                                            #    print("Nodo ya removido.")
"""

