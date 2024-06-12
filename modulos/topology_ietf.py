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
import networkx
import hashlib

from time import sleep
from datetime import datetime
#sys.path.append('cdn-alto/')
#sys.path.append('alto-ale/')
from ipaddress import ip_address
from modulos.alto_module import AltoModule


DEFAULT_ASN = 1
RR_BGP_0 = "50.50.50.1"
#RR_BGP = BGP_INFO['bgp']['ip']
MAX_VAL = 16777214

class TopologyIetf(AltoModule):

    def __init__(self, mb):
        super().__init__(mb)
        '''        self.ietf_process = 0
        self.props = {}
        self.pids = {}'''
        self.topology = networkx.Graph()
        self.cost_map = {}
        self.router_ids = []
        self.ts = {}
        
        
    ### Manager function       
    def manage_topology_updates(self):
        while 1:
            #sleep(15)
            sleep(5)
            self.manage_updates()


    def manage_updates(self):
        '''
        Receives topology information from the PCE by the Southaband Interface and creates/updates the graphs
        Realizes an iterational analisis, reviewing each network: if two networks are the same but by different protocols, they must to be merged.
        Three attributes on each network: dic[ips], dic[interfaces] and graph[links]
        '''
        #Diccionario nodo-id:nombre
        nodos = {}
        #Disccionario Nodo-id:prefijos
        prefijos = {}
        #Diccionario nodo-id:[(interfaz, ip)]
        tps = {}
        #Lista de enlaces
        links = []
        full_path = os.path.join("./", "ietf2_prueba.json")
        with open(full_path, 'r') as archivo:
            self.vtag = hashlib.sha3_384((str(int(datetime.timestamp(datetime.now())*1000000))).encode()).hexdigest()[:64]
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
                        if "prefix" in nodo["ietf-l3-unicast-topology:l3-node-attributes"].keys():
                            prefijos[nodo["node-id"]] = nodo["ietf-l3-unicast-topology:l3-node-attributes"]["prefix"]
                        if "ietf-network-topology:termination-point" in nodo.keys():
                            for tp in nodo["ietf-network-topology:termination-point"]:
                                tps[nodo["node-id"]].append(str(nodos[nodo["node-id"]]) + ' ' +  str(tp["tp-id"]))
                        pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.get_hex_id(nodo["node-id"]))
                        if pid_name not in self.pids:
                            self.pids[pid_name] = {}
                        if 'ipv4' not in self.pids[pid_name]:
                            self.pids[pid_name]['ipv4']=[]
                        if nodo['node-id'] not in self.pids[pid_name]['ipv4']:
                            self.pids[pid_name]['ipv4'].append( nodo['node-id'])
                        self.topology.add_node(nodo['node-id'])
                    
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
                #print("Numero de enlaces:  ",len(links))        
                # Una vez funciona todo, en vez de almacenarlo en diccionarios los guardamos en un grafo. -> Los nodos se pueden ir pasando ya arriba.
                # Ahora mismo va todo correcto, falta pasar los a,b a PID en vez de node-id.
            for link in links:
                if int(link[1])>=0:
                    self.topology.add_edge(link[0][0], link[0][1], weight=int(link[1]))
                    self.ejes[(link[0][0], link[0][1])] = int(link[1])
                    #print("Hola Mundo")
                    #self.ejes.append((link[0][0], link[0][1], int(link[1])))
            # Hay que revisar qué diccionarios seguirían haciendo falta.
            # Dado que bgp lo representa con node-id - node-id, quizás es importante unificar la representación que se muestre. (done)
            # Qué hacemos con las interfaces? Las mostramos en los ejes o no hace falta? Guardamos una lista de enlaces donde se vean cómo se conectan?
            self.compute_costmap()
            datos = str(self.pids).replace("'", '"')
            nodos = list(set(self.topology.nodes()))
            snodos = str(nodos).replace("'", '"')
            prefijos = str(prefijos).replace("'", '"')
            print("Nº de enlaces cargados:  " + str(len(self.topology.edges)))
            z_ejes = [(tupla[0], tupla[1], self.ejes[tupla]) for tupla in self.ejes]
            #print(str(z_ejes))
            data = '{"pids":'+datos+',"nodes-list": '+snodos+',"costs-list": '+str(z_ejes)+',"prefixes": '+prefijos+"}"
            self.return_info(2,0,1, data)
                        

