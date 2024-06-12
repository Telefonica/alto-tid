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

import sys
import json
import hashlib
from datetime import datetime
sys.path.append('cdn-alto/')
from modulos.bgp.manage_bgp_speaker import ManageBGPSpeaker
sys.path.append('alto-ale/')
from modulos.alto_module import AltoModule

DEFAULT_ASN = 0
RR_BGP_0 = "50.50.50.1"
#RR_BGP = BGP_INFO['bgp']['ip']


class TopologyBGP(AltoModule):

    def __init__(self, mb):
        super().__init__(mb)
        self.exabgp_process = ManageBGPSpeaker().check_tcp_connection()

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
            tipo = -1
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
                                    
                    tipo = 1
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
                    tipo = 0
                #self.__compute_costmap()
                #Aquí deberíamos mandar periódicamente la info al ALTO jefe.
                datos = str(self.__pids).replace("'", '"')
                data = '{"pids":'+datos+',"costs-list": '+str(self.ejes)+"}"
                #print(str(data))
                self.return_info(0,tipo,1,data)
