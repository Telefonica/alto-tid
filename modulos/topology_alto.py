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
import json
import hashlib

from time import sleep
from datetime import datetime
from modulos.alto_module import AltoModule

DEFAULT_ASN = 0


class TopologyAlto(AltoModule):

    def __init__(self, mb, ruta):
        super().__init__(mb)
        self.maps_directory = ruta
        

   ### Manager function       
    def manage_topology_updates(self):
        ccambios = 0
        ncambios = 0
        while 1:
            #sleep(15)
            ccambios, ncambios = self.manage_updates(ccambios, ncambios)
            sleep(5)


    def manage_updates(self, cambios, ncambios):
        '''
        Receives topology information from the PCE by the Southaband Interface and creates/updates the graphs
        Realizes an iterational analisis, reviewing each network: if two networks are the same but by different protocols, they must to be merged.
        Three attributes on each network: dic[ips], dic[interfaces] and graph[links]
        '''
        
        #Diccionario nodo-id:nombre
        nodos = {}
        #Disccionario Nodo-id:prefijos
        prefijos = {}
        #Lista de enlaces
        links = []
        
        cost_path = os.path.join(self.maps_directory, "cost-map.json")
        with open(cost_path, 'r') as archivo:
            self.vtag = hashlib.sha3_384((str(int(datetime.timestamp(datetime.now())*1000000))).encode()).hexdigest()[:64]

            #while True:
            deluro = archivo.read()
            d_json = json.loads(str(deluro))
           
            # Load nodes
            nodos = list(d_json.keys())    
                    
            # Load links
            for nodo in nodos:
                for par in d_json[nodo].keys():
                    if d_json[nodo][par] == 1:
                        links.append((nodo,par,1))
               
            # Load networks
            net_path = os.path.join(self.maps_directory, "network-map.json")            
            with open(net_path, 'r') as archivo2:
                deluro2 = archivo2.read()
                prefijos = json.loads(str(deluro2))
            
            if cambios != hashlib.sha3_384(deluro.encode()):
                cambios = hashlib.sha3_384(deluro.encode())
                if ncambios != hashlib.sha3_384(deluro2.encode()):
                    ncambios = hashlib.sha3_384(deluro2.encode())                                                
                    snodos = str(nodos).replace("'", '"')
                    prefijos = str(prefijos).replace("'", '"')
                    #slinks = str(links).replace("'", '"').replace("(", "[").replace(")","]")
                    #print("SLINKS:\n",slinks)
                    print("Topology loaded")
                    data = '{"pids":'+ '""' +',"nodes-list": '+snodos+',"costs-list": '+ str(links) +',"prefixes": '+prefijos+"}"
                    print(data)
                    self.return_info(2,0,1, data)
            
            return cambios, ncambios
                        

