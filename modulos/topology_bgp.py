#!/usr/bin/env python3

import sys
import json
import hashlib

from time import sleep
from datetime import datetime
sys.path.append('cdn-alto/')
from modulos.bgp.manage_bgp_speaker import ManageBGPSpeaker
sys.path.append('alto-ale/')
#from ipaddress import ip_address, IPv4Address
from modulos.alto_module import AltoModule

DEFAULT_ASN = 0
RR_BGP_0 = "50.50.50.1"
#RR_BGP = BGP_INFO['bgp']['ip']


class TopologyBGP(AltoModule):

    def __init__(self, mb):
        super().__init__(mb)
        self.exabgp_process = ManageBGPSpeaker().check_tcp_connection()
        '''self.__props = {}
        self.__pids = {}
        self.__topology = networkx.Graph()
        self.__cost_map = {}
        self.__router_ids = []
        self.__vtag = 0
        self.mailbox = mb

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

    def return_info(self, proto, msn):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        msg = "{'src':" + str(proto) +", 'map':" + str(msn) + "}"
        s.sendto(msg.encode(), self.mailbox)
'''

    ### Topology generation and information recopilation functions
    def __load_topology(self, lsa, igp_metric):
        if lsa.get('ls-nlri-type') == 'bgpls-link':
            # Link information
            src = self._get_info_from_node_descript_list(lsa['local-node-descriptors'], 'router-id')
            dst = self._get_info_from_node_descript_list(lsa['remote-node-descriptors'], 'router-id')
            for i, j in zip(src, dst):
                self.ejes.append((i, j, igp_metric))
        if lsa.get('ls-nlri-type') == "bgpls-node":
            # If ls-nlri-type is not present or is not of type bgpls-link or bgpls-prefix-v4
            # add node to topology if not present
            node_descriptors = self._get_info_from_node_descript_list(lsa['node-descriptors'], 'router-id')
            for nd in node_descriptors:
                if nd not in self.__pids.values():
                    auts=self._get_info_from_node_descript_list(lsa['node-descriptors'], 'autonomous-system', nd)
                    if auts == []: 
                        print("Tremenda F " + str(nd))
                        auts = 0
                    pid = self.__obtain_pid(nd, auts)    
                    self.__pids[pid] = nd



    ### Manager function

    def manage_topology_updates(self):
        """
        Reads stdout of process exabgp. It reads line by line
        Decoded update messages from exabgp are used to build the netwokmap and costmap
        :return:
        """
        pids_to_load = {RR_BGP_0: {'ipv4': {}}}
        while True:
            line = self.exabgp_process.stdout.readline().strip()
            tipo = ["routingcost",]
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
                                    #print("hola load")
                                    self.__load_topology(prefix, igp_metric)
                                    #self.__load_pid_prop(prefix, ls_area_id)
                        elif is_bgp:
                            for next_hop, prefix in is_bgp.items():
                                for nlri in prefix:
                                    #print("hola pid" + str(pids_to_load))
                                    #pid = self.__obtain_pid(nd, auts)
                                    #self.__pids[pid] = nd
                                    pids_to_load[neighbor_ip_address]['ipv4'][nlri['nlri']] = {'next-hop': next_hop}
                                    
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
                #self.__compute_costmap()
                #Aquí deberíamos mandar periódicamente la info al ALTO jefe.
                datos = str(self.__pids).replace("'", '"')
                data = '{"pids":'+datos+',"costs-list": '+str(self.ejes)+"}"
                #print(str(data))
                self.return_info(0,tipo,1,data)
