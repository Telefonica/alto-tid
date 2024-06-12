#!/usr/bin/env python3
# © 2024 Telefónica Innovación Digital
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


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
sys.path.append('/home/ubuntu/docker-alto/network_exposure/')
#from bgp.manage_bgp_speaker import ManageBGPSpeaker
sys.path.append('alto-ale/')
from kafka_ale.kafka_api import AltoProducer
#from api_pybatfish import BatfishManager
from yang_alto import RespuestasAlto
from ipaddress import ip_address, IPv4Address

DEFAULT_ASN = 0
RR_BGP_0 = "50.50.50.1"
#RR_BGP = BGP_INFO['bgp']['ip']


class TopologyCreator:

    def __init__(self, exabgp_process, mode):
        self.exabgp_process = exabgp_process
        self.__props = {}
        self.__pids = {}
        self.__topology = networkx.Graph()
        self.__cost_map = {}
        self.__router_ids = []
        # set path where to write result json files
        self.__topology_writer = TopologyFileWriter('/root/')
        if mode:
            self.kafka_p = AltoProducer("localhost", "9092")
        #self.kafka_p = AltoProducer("localhost", "9093")
        self.__ts = {}
        #self.bfm = BatfishManager()
        self.__vtag = 0
        self.__resp = RespuestasAlto()

    ### Static Methods

    @staticmethod
    def __discard_message_from_protocol_id(message, discard_protocols):
        """Discard message if protocol is inside discard_protocols list"""
        return message["protocol-id"] in discard_protocols

    @staticmethod
    def __get_hex_id(ip):
        """Get hexadecimal value for certain IP
        :param: ip string"""
        return ''.join(['%02x' % int(w) for w in ip.split('.')])

    @staticmethod
    def __check_is_hex(hex_value):
        try:
            int(hex_value, 16)
            return True
        except ValueError:
            return False

    @staticmethod
    def __split_router_ids(router_id: str):
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
    def __check_if_router_id_is_hex(router_id):
        return router_id.isnumeric()

    @staticmethod
    def __hex_to_ip(hex_ip):
        hex_ip = hex_ip.strip("0")
        addr_long = int(hex_ip, 16) & 0xFFFFFFFF
        struct.pack("<L", addr_long)
        return socket.inet_ntoa(struct.pack("<L", addr_long))

    @staticmethod
    def __reverse_ip(reversed_ip):
        l = reversed_ip.split(".")
        return '.'.join(l[::-1])



    ### Auxiliar methods

    def __ip_type(self, prefix):
        ip=prefix.split("/")[0]
        return "IPv4" if type(ip_address(ip)) is IPv4Address else "IPv6"

    def __obtain_pid(self, router):
        """Returns the hashed PID of the router passed as argument. 
            If the PID was already mapped, it uses a dictionary to access to it.
        """
        tsn = int(datetime.timestamp(datetime.now())*1000000)
        rid = self.__get_hex_id(router) if not self.__check_is_hex(router) else router
        if rid not in self.__ts.keys():
            self.__ts[rid] = tsn
        else:
            tsn = self.__ts[rid]
        hash_r = hashlib.sha3_384((router + str(tsn)).encode())
        return ('pid%d:%s:%d' % (DEFAULT_ASN, hash_r.hexdigest()[:32], tsn))

    def __create_pid_name(self, lsa, descriptors, area_id):
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
            pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.__get_hex_id(router_id) if not self.__check_is_hex(router_id) else router_id)
            #pid_name = self.__obtain_pid(router_id)
            origin = (autonomous_system, domain_id, area_id, router_id)
            if pid_name not in self.__props:
                self.__props[pid_name] = []
            self.__props[pid_name].append(origin)

    def ___get_router_id_from_node_descript_list(self, node_descriptors, key: str):
        result = []
        for descriptor in node_descriptors:
            for key_d, value in descriptor.items():
                if key_d == key:
                    #print(value, key_d)
                    if self.__check_if_router_id_is_hex(value):
                        result.append(self.__split_router_ids(value))
                    elif "." in value:
                        result.append(value)
                    else:
                        result.append(self.__reverse_ip(self.__hex_to_ip(value)))
        return result

    def parseo_yang(self, mensaje, tipo):
        return str(tipo) + 'json{"alto-tid":"1.0","time":' + str(datetime.timestamp(datetime.now())) + ',"host":"altoserver-alberto","' + str(tipo) + '":' + str(mensaje) + '},}'



    ### Topology generation and information recopilation functions

    def __load_topology(self, lsa, igp_metric):
        if lsa.get('ls-nlri-type') == 'bgpls-link':
            # Link information
            src = self.___get_router_id_from_node_descript_list(lsa['local-node-descriptors'], 'router-id')
            dst = self.___get_router_id_from_node_descript_list(lsa['remote-node-descriptors'], 'router-id')
            for i, j in zip(src, dst):
                self.__topology.add_edge(i, j, weight=igp_metric)
        if lsa.get('ls-nlri-type') == 'bgpls-prefix-v4':
            # ToDo verify if prefix info is needed and not already provided by node-descriptors
            # Node information. Groups origin with its prefixes
            origin = self.___get_router_id_from_node_descript_list(lsa['node-descriptors'], "router-id")
            prefix = self.__split_router_ids(lsa['ip-reach-prefix'])
            for item in origin:
                if item not in self.__topology.nodes():
                    self.__topology.add_node(item)
                if 'prefixes' not in self.__topology.nodes[item]:
                    self.__topology.nodes[item]['prefixes'] = []
                self.__topology.nodes[item]['prefixes'].append(prefix)
        if lsa.get('ls-nlri-type') == "bgpls-node":
            # If ls-nlri-type is not present or is not of type bgpls-link or bgpls-prefix-v4
            # add node to topology if not present
            node_descriptors = self.___get_router_id_from_node_descript_list(lsa['node-descriptors'], 'router-id')
            self.__router_ids.append(node_descriptors)
            for node_descriptor in node_descriptors:
                if node_descriptor not in self.__topology.nodes():
                    self.__topology.add_node(node_descriptor)

    def __load_pid_prop(self, lsa, ls_area_id):
        if 'node-descriptors' in lsa:
            self.__create_pid_name(lsa, descriptors='node-descriptors', area_id=ls_area_id)
        if 'local-node-descriptors' in lsa:
            self.__create_pid_name(lsa, descriptors='local-node-descriptors', area_id=ls_area_id)
        if 'remote-node-descriptors' in lsa:
            self.__create_pid_name(lsa, descriptors='remote-node-descriptors', area_id=ls_area_id)

    def __load_pids(self, ipv4db):
        # self.__pids stores the result of networkmap
        for rr_bgp in [RR_BGP_0]:
            for prefix, data in ipv4db[rr_bgp]['ipv4'].items():
                pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.__get_hex_id(data['next-hop']))
                #pid_name = self.__obtain_pid(data['next-hop'])
                tipo=self.__ip_type(prefix)
                if pid_name not in self.__pids:
                    self.__pids[pid_name] = {}
                if tipo not in self.__pids[pid_name]:
                    self.__pids[pid_name][tipo]=[]
                if prefix not in self.__pids[pid_name][tipo]:
                    self.__pids[pid_name][tipo].append(prefix)

    def __compute_costmap(self):
        # shortest_paths is a dict by source and target that contains the shortest path length for
        # that source and destination
        shortest_paths = dict(networkx.shortest_paths.all_pairs_dijkstra_path_length(self.__topology))
        for src, dest_pids in shortest_paths.items():
            src_pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.__get_hex_id(src))
            #src_pid_name = self.__obtain_pid(src)
            for dest_pid, weight in dest_pids.items():
                dst_pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.__get_hex_id(dest_pid))
                #dst_pid_name = self.__obtain_pid(dest_pid)
                if src_pid_name not in self.__cost_map:
                    self.__cost_map[src_pid_name] = {}
                self.__cost_map[src_pid_name][dst_pid_name] = weight
    


    ### RFC7285 functions
    def get_costs_map_by_pid(self, pid):
        #pid = "pid0:" + str(npid)
        #print(pid)
        #print(str(self.__pids))
        if pid in self.__cost_map.keys():
            #print(str(self.__pids))
            #print(str(self.__cost_map))
            return self.__resp.crear_respuesta("filtro", "networkmap-default", self.__vtag, str(self.__cost_map[pid]))
        else:
            return "404: Not Found"

    def get_properties(self, pid):
        #return str(self.bf.session.q.nodeProperties().answer().frame())
        return "Implementation in proccess. Sorry dude"

    def get_endpoint_costs(self, pid):
        return "Implementation in proccess. Sorry dude"

    def get_maps(self):
        return ('{"pids_map":' + self.get_pids() + ', "costs_map":' + self.get_costs_map() + '}')

    def get_costs_map(self):
        return self.__resp.crear_respuesta("cost-map", "networkmap-default", self.__vtag, str(self.__cost_map))

    def get_pids(self):
        return self.__resp.crear_respuesta("pid-map", "networkmap-default", self.__vtag, str(self.__pids))

    def get_directory(self):
        return self.__resp.indice()

    ### Ampliation functions
    
    def shortest_path(self, a, b):
        try:
            return networkx.dijkstra_path(self.__topology, a, b)
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



    ### Manager function

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
                self.__vtag = hashlib.sha3_384((str(int(datetime.timestamp(datetime.now())*1000000))).encode()).hexdigest()[:64]
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
                                    if self.__discard_message_from_protocol_id(prefix, [4, 5]):
                                        continue
                                    self.__load_topology(prefix, igp_metric)
                                    self.__load_pid_prop(prefix, ls_area_id)
                        elif is_bgp:
                            for next_hop, prefix in is_bgp.items():
                                for nlri in prefix:
                                    pids_to_load[neighbor_ip_address]['ipv4'][nlri['nlri']] = {'next-hop': next_hop}
                                    self.__load_pids(pids_to_load)

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
                                    self.__topology.remove_edge(self.__split_router_ids(u), self.__split_router_ids(v))
                                except:
                                    print("Eje ya removido.")
                
                self.__compute_costmap()
                self.__topology_writer.write_same_ips(self.__router_ids)
                self.__topology_writer.write_pid_file(self.__pids)
                self.__topology_writer.write_cost_map(self.__cost_map)

            if bool(self.__cost_map) :
                if mode:
                    self.kafka_p.envio_alto('alto-costes', self.__cost_map, 0)
               
    def manage_ietf_speaker_updates(self):
        '''
        Receives topology information from the PCE by the Southaband Interface and creates/updates the graphs
        Realizes an iterational analisis, reviewing each network: if two networks are the same but by different protocols, they must to be merged.
        Three attributes on each network: dic[ips], dic[interfaces] and graph[links]
        '''
        #Diccionario nodo-id:nombre
        nodos = {}
        #Diccionario nodo-id:[(interfaz, ip)]
        tps = {}
        #Lista de enlaces
        links = []
        full_path = os.path.join("/root/", "ietf_prueba.json")
        with open(full_path, 'r') as archivo:
            self.__vtag = hashlib.sha3_384((str(int(datetime.timestamp(datetime.now())*1000000))).encode()).hexdigest()[:64]
            #while True:
            deluro = archivo.read()
            d_json = json.loads(str(deluro))
            #print("Tipo = " +  str(type(d_json)) + "\nMensaje = " + str(d_json))
            ietf_networks = d_json["ietf-network:networks"]
            if ietf_networks == '':
                return
            #Creo un diccionario con todas las redes que hay y lo recorro para buscar las válidas
            for net in ietf_networks["network"]:
                if "node" in net.keys() and "ietf-network-topology:link" in net.keys():
                    for nodo in net["node"]:
                        #Realizo un macheo de los IDs de los nodos con el nombre y el/los prefijo/s.
                        nodos[nodo["node-id"]] = nodo["ietf-l3-unicast-topology:l3-node-attributes"]["name"]
                        tps[nodo["node-id"]] = []
                        if "ietf-network-topology:termination-point" in nodo.keys():
                            for tp in nodo["ietf-network-topology:termination-point"]:
                                tps[nodo["node-id"]].append(str(nodos[nodo["node-id"]]) + ' ' +  str(tp["tp-id"]))
                        pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.__get_hex_id(nodo["node-id"]))
                        if pid_name not in self.__pids:
                            self.__pids[pid_name] = {}
                        if 'ipv4' not in self.__pids[pid_name]:
                            self.__pids[pid_name]['ipv4']=[]
                        if nodo['node-id'] not in self.__pids[pid_name]['ipv4']:
                            self.__pids[pid_name]['ipv4'].append( nodo['node-id'])
                        self.__topology.add_node(nodo['node-id'])
                    
                    # Falta listar los enlaces y guardarlos.
                    for link in net["ietf-network-topology:link"]:
                        a,b = link["link-id"].split(" - ")
                        if a == '' or b == '':
                            break
                        a1 = a.split(' ')[0]
                        b1 = b.split(' ')[0]
                        for k in nodos.keys():
                            if nodos[k] == a1:
                                a = k
                            elif nodos[k] == b1:
                                b = k
                        links.append(((a,b),link["ietf-l3-unicast-topology:l3-link-attributes"]["metric1"]))
                        
                # Una vez funciona todo, en vez de almacenarlo en diccionarios los guardamos en un grafo. -> Los nodos se pueden ir pasando ya arriba.
                # Ahora mismo va todo correcto, falta pasar los a,b a PID en vez de node-id.
                for link in links:
                    self.__topology.add_edge(link[0][0], link[0][1], weight=int(link[1]))

            # Hay que revisar qué diccionarios seguirían haciendo falta.
            # Dado que bgp lo representa con node-id - node-id, quizás es importante unificar la representación que se muestre. (done)
            # Qué hacemos con las interfaces? Las mostramos en los ejes o no hace falta? Guardamos una lista de enlaces donde se vean cómo se conectan?
            print("Done")
            self.__compute_costmap()
            self.__topology_writer.write_same_ips(self.__router_ids)
            self.__topology_writer.write_pid_file(self.__pids)
            self.__topology_writer.write_cost_map(self.__cost_map)
            print(str(self.get_maps()))
                        


class TopologyFileWriter:

    def __init__(self, output_path):
        self.output_path = output_path
        self.pid_file = 'pid_file.json'
        self.__cost_map_file = 'cost_map.json'
        self.same_node_ips = "router_ids.json"

    def write_file(self, file_name, content_to_write):
        """Writes file_name in output_file"""
        full_path = os.path.join(self.output_path, file_name)
        with open(full_path, 'w') as out_file:
            json.dump(content_to_write, out_file, indent=4)

    def write_pid_file(self, content):
        self.write_file(self.pid_file, content)

    def write_cost_map(self, content):
        self.write_file(self.__cost_map_file, content)

    def write_same_ips(self, content):
        self.write_file(self.same_node_ips, content)



if __name__ == '__main__':
    speaker_bgp = ManageBGPSpeaker()
    exabgp_process = speaker_bgp.check_tcp_connection()
    
    topology_creator = TopologyCreator(exabgp_process,0)
    topology_creator.manage_ietf_speaker_updates()
