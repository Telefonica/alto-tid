#!/usr/bin/env python3
# © 2024 Telefónica Innovación Digital, All rights reserved


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
        self.old_ejes  = []
        self.old_nodos = {}
        self.nodos = {}        
        
    ### Manager function       
    def manage_topology_updates(self):
        while 1:
            sleep(3)
            self.manage_updates()
            sleep(100)


    def process_topology(self, topology_data):
            # Diccionario nodo-id:nombre para cada topología
            nodos = {}
            # Diccionario Nodo-id:prefijos
            prefijos = {}
            # Diccionario nodo-id:[(interfaz, ip)]
            tps = {}
            # Lista de enlaces
            links = []
            self.topology = networkx.Graph()
            print("TOPOLOGIA NODOS:\t", self.topology.nodes())
            print("TOPOLOGIA EJES:\t", self.topology.edges())
            ietf_networks = topology_data["ietf-network:networks"]
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
                        #pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.get_hex_id(nodo["node-id"]))
                        pid_name = nodo["node-id"]
                        if pid_name not in self.pids:
                            self.pids[pid_name] = {}
                        if 'ipv4' not in self.pids[pid_name]:
                            self.pids[pid_name]['ipv4']=[]
                        if nodo['node-id'] not in self.pids[pid_name]['ipv4']:
                            self.pids[pid_name]['ipv4'].append( nodo['node-id'])
                        print("NODO:\t", nodos[nodo['node-id']])
                        self.topology.add_node(nodos[nodo['node-id']])

                    # print("NODOS:\t", nodos)
                    # Falta listar los enlaces y guardarlos.
                    for link in net["ietf-network-topology:link"]:
                        a,b = link["link-id"].split("-")
                        if a == '' or b == '':
                            break
                        a1 = a.split('_')[0]
                        b1 = b.split('_')[0]
                        for k in nodos.keys():
                            if k == a1:
                                a = nodos[k]
                            elif k == b1:
                                b = nodos[k]
                        links.append(((a,b),link["ietf-l3-unicast-topology:l3-link-attributes"]["routingcost"]))
                #print("Numero de enlaces:  ",len(links))
                # Una vez funciona todo, en vez de almacenarlo en diccionarios los guardamos en un grafo. -> Los nodos se pueden ir pasando ya arriba.
                # Ahora mismo va todo correcto, falta pasar los a,b a PID en vez de node-id.
            for link in links:
                if int(link[1])>=0:
                    self.topology.add_edge(link[0][0], link[0][1], weight=int(link[1]))
                    self.ejes[(link[0][0], link[0][1])] = int(link[1])



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
        # full_path = os.path.join("./", "ietf2_prueba.json")
        print("TOPOLOGIA NODOS:\t", self.topology.nodes())
        print("TOPOLOGIA EJES:\t", self.topology.edges())
        full_path = os.path.join("./", "topology.json")
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
                        #pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.get_hex_id(nodo["node-id"]))
                        pid_name = nodo["node-id"]
                        if pid_name not in self.pids:
                            self.pids[pid_name] = {}
                        if 'ipv4' not in self.pids[pid_name]:
                            self.pids[pid_name]['ipv4']=[]
                        if nodo['node-id'] not in self.pids[pid_name]['ipv4']:
                            self.pids[pid_name]['ipv4'].append( nodo['node-id'])
                        self.topology.add_node(nodos[nodo['node-id']])
                   
                    # print("NODOS:\t", nodos)
                    # Falta listar los enlaces y guardarlos.
                    for link in net["ietf-network-topology:link"]:
                        a,b = link["link-id"].split("-")
                        if a == '' or b == '':
                            break
                        a1 = a.split('_')[0]
                        b1 = b.split('_')[0]
                        for k in nodos.keys():
                            if k == a1:
                                a = nodos[k]
                            elif k == b1:
                                b = nodos[k]
                        properties = {"weight" : 10}
                        for elemento, peso in link["ietf-l3-unicast-topology:l3-link-attributes"].items():
                            if elemento == "routingcost": 
                                properties["weight"] = peso 
                            elif isinstance(elemento, str) and (len(elemento.split(":")) < 2): 
                                properties[elemento] = peso 
                        links.append(((a,b),properties))
                #print("Numero de enlaces:  ",len(links))        
                # Una vez funciona todo, en vez de almacenarlo en diccionarios los guardamos en un grafo. -> Los nodos se pueden ir pasando ya arriba.
                # Ahora mismo va todo correcto, falta pasar los a,b a PID en vez de node-id.
            for link in links:
                #if int(link[1]["weight"])>=0:
                print("EJE:\t", link[0][0], link[0][1], link[1])
                self.topology.add_edge(link[0][0], link[0][1], **link[1])
                self.ejes[(link[0][0], link[0][1])] = int(link[1]["weight"])
                    #print("Hola Mundo")
                    #self.ejes.append((link[0][0], link[0][1], int(link[1])))
            # Hay que revisar qué diccionarios seguirían haciendo falta.
            # Dado que bgp lo representa con node-id - node-id, quizás es importante unificar la representación que se muestre. (done)
            # Qué hacemos con las interfaces? Las mostramos en los ejes o no hace falta? Guardamos una lista de enlaces donde se vean cómo se conectan?
            # self.compute_costmap()
            datos = str(self.pids).replace("'", '"')
            # nodos = list(set(self.topology.nodes()))
            # snodos = str(nodos).replace("'", '"')
            #prefijos = str(prefijos).replace("'", '"')
            for nodo, nombre in nodos.items():
                self.nodos[nodo] = nombre
            print("Nº de enlaces cargados:  " + str(len(self.topology.edges)))
            z_ejes = [(tupla[0], tupla[1], self.topology.get_edge_data(tupla[0], tupla[1])) for tupla in self.ejes]
            l_nodos = list(set(self.topology.nodes()))
            #print(str(z_ejes))
            data = {"pids":nodos,"nodes-list":l_nodos,"costs-list": z_ejes,"prefixes": prefijos}
            #data = '{"pids":'+datos+',"nodes-list": '+snodos+',"costs-list": '+str(z_ejes)+',"prefixes": '+prefijos+"}"
            if (l_nodos != self.old_nodos) or (z_ejes != self.old_ejes):
                print("DATA:\t", data)
                print("OLD NODOS:\t", self.old_nodos)
                print("OLD EJES:\t", self.old_ejes)
                self.return_info(2,0,1, data)
                self.old_ejes  = z_ejes
                self.old_nodos = l_nodos
                        
    def manage_update_topology(self, update_topology):
        d_json = update_topology
        # print(d_json)
        self.process_topology(d_json)
        return self.topology

