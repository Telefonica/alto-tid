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


class TopologyQKD(AltoModule):

    def __init__(self, mb, ruta):
        super().__init__(mb)
        self.directory = ruta


    ### Manager function
    def manage_topology_updates(self):
        ccambios = 0
        while 1:
            #sleep(15)
            ccambios = self.manage_updates(ccambios)
            sleep(5)
            
    def manage_updates(self, cambios):
        """
        Reads stdout of process exabgp. It reads line by line
        Decoded update messages from exabgp are used to build the netwokmap and costmap
        :return:
        """
        #List of Nodes IDs
        nodos = []
        #Disccionario Nodo-id:prefijos
        prefijos = {}
        #Lista de enlaces
        links = []
        
        cost_path = os.path.join(self.directory, "qkd_topology.json")
        #cost_path = os.path.join(self.directory, "qkd_topology_remote.json")
        with open(cost_path, 'r') as archivo:
            self.vtag = hashlib.sha3_384((str(int(datetime.timestamp(datetime.now())*1000000))).encode()).hexdigest()[:64]

            #while True:
            deluro = archivo.read()
            d_json = json.loads(str(deluro))

            if cambios != hashlib.sha3_384(deluro.encode()).hexdigest():
                cambios = hashlib.sha3_384(deluro.encode()).hexdigest()
                # Load nodes
                nodos = [ nodo["id"] for nodo in d_json["devices"] ]
                # Load links
                links = [ (n["source"], n["target"], 1) for n in d_json["links"] ]        
                # Load networks --> Not in this version
                prefijos = {}
                      
                snodos = str(nodos).replace("'", '"')
                prefijos = str(prefijos).replace("'", '"')
                #slinks = str(links).replace("'", '"').replace("(", "[").replace(")","]")
                #print("SLINKS:\n",slinks)
                print("Topology loaded")
                data = '{"pids":'+ '""' +',"nodes-list": '+snodos+',"costs-list": '+ str(links) +',"prefixes": '+prefijos+"}"
                print(data)
                self.return_info(2,0,1, data)
            
            return cambios
