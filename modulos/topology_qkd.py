#!/usr/bin/env python3
# © 2024 Telefónica Innovación Digital, All rights reserved
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
            sleep(1)
            ccambios = self.manage_updates(ccambios)
            sleep(4)
            
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
        
        #cost_path = os.path.join(self.directory, "qkd-topology.json")
        cost_path = os.path.join(self.directory, "qkd-topology-remote.json")
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