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

import ipaddress
import os
import json
import re
import struct
import networkx
import socket
import threading
import ipaddress
import hashlib
import yaml

from time import sleep
from datetime import datetime
from api.kafka_ale.kafka_api import AltoProducer
from modulos.topology_alto import TopologyAlto
from modulos.topology_bgp import TopologyBGP
from modulos.topology_qkd import TopologyQKD
from yang_alto import RespuestasAlto
#from ipaddress import ip_address, IPv4Address
from modulos.topology_bgp import TopologyBGP
from modulos.topology_ietf import TopologyIetf
from api.desire.alto_http import AltoHttp
#from api.web.alto_http import AltoHttp

DEFAULT_ASN = 0
DEF_PORT = 8080
REMOTE_PORT = 8080
DEF_IP = "127.0.0.1"
ERRORES = { "sintax" : "E_SYNTAX", "campo" : "E_MISSING_FIELD", "tipo" : "E_INVALID_FIELD_TYPE", "valor" : "E_INVALID_FIELD_VALUE" }
class TopologyCreator:

    def __init__(self, modules, mode=0, ip="127.0.0.1", puerto=8000, portm=5000):
        # Necesita que depuremos las variables: Qué es necesario? Faltan algunas? Cómo referenciar las APIs et al?
        self.__d_modules = modules
        self.__redes = []
        self.__topology = networkx.Graph()
        self.__cost_map = {}
        self.__net_map = {}
        self.bordernodes = {}
        self.ip = ip
        self.puerto = puerto
        self.port_module = portm
        # set path where to write result json files
        self.__topology_writer = TopologyFileWriter('/root/')
        if mode:
            self.__api = AltoProducer("localhost", "9092")
        else:
            self.__api = AltoHttp(self, ip, puerto)        
        self.__vtag = 0
        self.__respuesta = RespuestasAlto()
        #self.kafka_p = AltoProducer("localhost", "9093")
        self.ts = {}
        self.__endpoints = {}
        #self.known_servers = [ ["localhost", 8082], ["localhost",8081]]

    ######################
    ### Static Methods ###
    ######################
    # Relacionadas con BGP. Hay que migrarlas al módulo de BGP pero conservando que los chequeos se realicen.
    @staticmethod
    def get_hex_id(ip):
        """Get hexadecimal value for certain IP
        :param: ip string"""
        return ''.join(['%02x' % int(w) for w in ip.split('.')])

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

    @staticmethod
    def check_is_hex(hex_value):
        try:
            int(hex_value, 16)
            return True
        except ValueError:
            return False

    @staticmethod
    def check_if_router_id_is_hex(router_id):
        return router_id.isnumeric()
    
    @staticmethod
    def reverse_ip(reversed_ip):
        l = reversed_ip.split(".")
        return '.'.join(l[::-1])

    @staticmethod
    def hex_to_ip(hex_ip):
        hex_ip = hex_ip.strip("0")
        addr_long = int(hex_ip, 16) & 0xFFFFFFFF
        struct.pack("<L", addr_long)
        return socket.inet_ntoa(struct.pack("<L", addr_long))

    ######################
    ### Public methods ###
    ######################


    def get_router_id(self, value):
        if self.check_if_router_id_is_hex(value):
            return self.split_router_ids(value)
        elif "." in value:
            return value
        else:
            return self.reverse_ip(self.hex_to_ip(value))
    
    def run_api(self):
        self.__api.run()
    
    def parseo_yang(self, mensaje, tipo):
        '''
        It creates a message in the format expected by the ALTO client just as the RFC defined.
        Under evaluation for Stage 2.0.
        Imputs: 
            mensaje: Map to be sent.
            tipo: type of map sent.
        Output: formated message with some metadata.
        '''
        return str(tipo) + 'json{"alto-tid":"1.0","time":' + str(datetime.timestamp(datetime.now())) + ',"host":"altoserver-alberto","' + str(tipo) + '":' + str(mensaje) + '},}'

    def compute_netmap(self, asn, redes):
        '''
        This funtion evaluates the list of networks founded and associates them to the node in the topology that enroutes it.
        Imput:
            asn: autonomous system where the network is.
            redes: list of networks.
        '''
        net_map = {}
        for router in redes.keys():
            ipv4 = []
            ipv6 = []
            for ip in redes[router]:
                if not ip["prefix"].endswith("/3", -3, -1):
                    #print(ip[-3:-1])
                    ipv4.append(str(ipaddress.IPv4Network(ip["prefix"], strict=False)))
                #try:
                #    if type(ipaddress.ip_network(ip)) is IPv4Network:clear
                #else:
                #        ipv6.append(ip)
                #except:
                #    print("Invalid IP" + str(ip))
            pid = 'pid%d:%s' % (asn, self.get_hex_id(router))
            #pid = self.cyphered_pid(router, asn)
            #pid = self.obtain_pid(router)
            if len(ipv4):
                if pid not in net_map.keys():
                    net_map[pid] = {}
                    #self.__net_map[pid]['ipv4'] = []
                #self.__net_map[pid]["ipv4"] = ipv4
                net_map[pid]['ipv4'] = ipv4
            if len(ipv6):
                net_map[pid]["ipv6"] = ipv6
        return net_map

    def compute_costmap(self, topo=None):
        # shortest_paths is a dict by source and target that contains the shortest path length for
        # that source and destination
        if topo == None:
            topo = self.__topology
        cost_map = {}
        shortest_paths = dict(networkx.shortest_paths.all_pairs_dijkstra_path_length(topo))
        for src, dest_pids in shortest_paths.items():
            src_pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.get_hex_id(src))
            #src_pid_name = self.obtain_pid(src)
            for dest_pid, weight in dest_pids.items():
                dst_pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.get_hex_id(dest_pid))
                #dst_pid_name = self.obtain_pid(dest_pid)
                if src_pid_name not in cost_map:
                    cost_map[src_pid_name] = {}
                cost_map[src_pid_name][dst_pid_name] = weight
                # if src in self.nodos:
                #     if src not in cost_map:
                #         cost_map[src] = {}
                #     cost_map[src][dest_pid] = weight
                # else:
                #     # Si el nodo no pertenece a nuestra red, significa que es alcanzable a través de un border node nuestro.
                #     # Mapeamos Nodo_fuera : Nuestro nodo, para saber cuál es el BN con el que podemos alcanzar a ese nodo.
                #     # Modificar en Multihoming.
                #     self.bordernodes[src] = dest_pid
        return cost_map
    
    def obtain_pid(self, router):
        """Returns the hashed PID of the router passed as argument. 
            If the PID was already mapped, it uses a dictionary to access to it.
        """
        tsn = int(datetime.timestamp(datetime.now())*1000000)
        if len(router.split(":")) > 1:
            router = router.split(":")[1]
        rid = self.get_hex_id(router) if not self.check_is_hex(router) else router
        if rid not in self.ts.keys():
            self.ts[rid] = tsn
        else:
            tsn = self.ts[rid]
        hash_r = hashlib.sha3_384((router + str(tsn)).encode())
        return ('pid%d:%s:%d' % (DEFAULT_ASN, hash_r.hexdigest()[:32], tsn))
    
    def compute_pid_endpoint(self, endpoint):
        #Vamos a recibir la IP del
        ip_e = ipaddress.IPv4Address(endpoint)
        red = "0.0.0.0/-1"
        pid_e = 0
        #print(str( self.__net_map))
        for pid in self.__net_map:
            #print("pid", pid)
            for prefijo in self.__net_map[pid]["ipv4"]:
                if ip_e in ipaddress.IPv4Network(prefijo):
                    if int(prefijo.split("/")[1]) > int(red.split("/")[1]):
                        red = prefijo
                        pid_e = pid
        #print(endpoint,self.__net_map[pid_e]["ipv4"])
        return pid_e

    def launch_api(self):
        t_http = threading.Thread(target=self.http.run)
        t_http.start()

   
   
   ##############################################
   ###    Functions to be called by the API   ###
   ##############################################
   
    ### RFC7285 functions
    def get_costs_map_by_pid(self, pid):
        #pid = "pid0:" + str(npid)
        #print(pid)
        #print(str(self.__pids))
        if not pid:
            return str({"ERROR" : ERRORES["campo"], "syntax-error": "Missing PID."})
        if type(pid) is not str:
            return str({"ERROR" : ERRORES["tipo"], "syntax-error": "The PID type is incorrect. We need a string."})
        if pid in self.__cost_map.keys():
            #print(str(self.__pids))
            #print(str(self.__cost_map))
            mapa = self.__cost_map[pid]
            return self.__respuesta.crear_respuesta("filtro", "networkmap-default", self.__vtag, str(mapa))       
        else:
            for server in self.known_servers:
                if (server[1] != self.puerto):# or (server[0] != self.ip):
                    response = self.ask_other_alto_server(pid, server[0], server[1])
                    if response != "":
                        return response                   
            return str({"ERROR" : ERRORES["valor"], "syntax-error": "PID not found."})

    def get_properties(self, pid, properties=None):
        #return str(self.bf.session.q.nodeProperties().answer().frame())
        #pid = self.__compute_pid_endpoint(endpoint)
        if pid:
            if type(pid) is not str:
                return str({"ERROR" : ERRORES["tipo"], "syntax-error": "The PID type is incorrect. We need a string."})
            #if pid not in self.__topology.nodes():
            #    return str({"ERROR" : ERRORES["valor"], "syntax-error": "PID not found."})
            if properties:
                if type(properties) is not str:
                    return str({"ERROR" : ERRORES["tipo"], "syntax-error": "The Property type is incorrect. We need a string."})
                with open('./endpoints/properties.json','r') as archivo:
                    prop = json.load(archivo)
                    for usuario in prop["users"]:
                        result = {}
                        if usuario["ipv4"][0] == pid:
                            for propiedad in properties:
                                if propiedad in usuario["properties"].keys():
                                    result[propiedad] = usuario["properties"][propiedad]
                            if result:
                                for prop in properties:
                                    resp = {"ipv4": pid ,"properties": properties, "values": [result[prop] for prop in properties]}
                            else:
                                return str({"ERROR" : ERRORES["valor"], "syntax-error": f'{properties} not valid for {pid}'})
                return self.__respuesta.respuesta_prop("endpointprop", "my-default-network-map.prop", self.__vtag, str(resp))
            else:
                with open('./endpoints/properties.json','r') as archivo:
                    prop = json.load(archivo)
                    for usuario in prop["users"]:
                        result = {}
                        if usuario["ipv4"][0] == pid:
                            resp = usuario                        
                            return self.__respuesta.respuesta_prop("endpointprop", "my-default-network-map.prop", self.__vtag, str(resp))
                #print(resp)
                 
            #else:
            #    return str({"ERROR" : ERRORES["campo"], "syntax-error": "Properties not provided"})       
        #return str(self.bf.session.q.nodeProperties().answer().frame())
        return str({"ERROR" : ERRORES["campo"], "syntax-error": "PID not provided"})

    def get_endpoint_costs(self, endpoint):
        pid = self.__endpoints.get(endpoint)
        if pid:
                return self.get_costs_map_by_pid(pid["pid"])
        else:
                return str({"ERROR" : ERRORES["valor"], "syntax-error": "Endpoint not found."})
        #return "Implementation in proccess. Sorry dude"

    def get_maps(self, filtro=None):
        if filtro == None:
            return ('{"network_map":' + self.get_net_map() + ', "costs_map":' + self.get_costs_map() + '}')
        else:
            return ('{"network_map":' + self.get_net_map(filtro) + ', "costs_map":' + self.get_costs_map(filtro) + '}')

    def get_costs_map(self, filtro=None):
        if filtro == None:
            return self.__respuesta.respuesta_costes("costmap","networkmap-default", self.__vtag, str(self.__cost_map))
        else:
            f_costmap = self.get_filtered_cost_map(filtro)
            if f_costmap == -1:
                return str({"ERROR" : ERRORES["campo"], "syntax-error": "Filter not valid."})
            return self.__respuesta.respuesta_costes("costmapfilter", "networkmap-default", self.__vtag, f_costmap)
            #return self.__respuesta.crear_respuesta("filtered-cost-map","networkmap-default", 0, self.get_filtered_cost_map(filtro))
        #return self.resp.crear_respuesta("cost-map", "networkmap-default", self.__vtag, str(self.__cost_map))

    def get_net_map(self, filtro=None):
        if filtro == None:
            return self.__respuesta.respuesta_pid("networkmap", "networkmap-default", self.__vtag, str(self.__net_map))
        else:
            f_netmap = self.get_filtered_network_map(filtro)
            if f_netmap == -1:
                return str({"ERROR" : ERRORES["campo"], "syntax-error": "Filter not valid."})
            return self.__respuesta.respuesta_pid("networkmapfilter","networkmap-default",self.__vtag, f_netmap)
            #return self.__respuesta.crear_respuesta("filtered-pid-map", "networkmap-default", self.__vtag, self.get_filtered_network_map(filtro))

    def get_directory(self):
        return self.__respuesta.indice()

    # Mover a un documento que sea de funciones qkd, y estas funciones serían importadas desde otro lugar.
    def get_qkd_properties(self, node=None):
        if node == None:
            return str({"ERROR" : ERRORES["valor"], "syntax-error": "PID not found."})
        if type(node) is not str:
            return str({"ERROR" : ERRORES["tipo"], "syntax-error": "The PID type is incorrect. We need a string."})
        if len(node.split(":"))>0:
            nnode = self.reverse_ip(self.hex_to_ip(node.split(":")[1]))
            print(nnode)
        else:
            nnode = self.reverse_ip(self.hex_to_ip(node))
            print(nnode)
        props = self.evaluate_qkd_endpoints(nnode)
        if props == -1:
            return str({"ERROR" : ERRORES["valor"], "syntax-error": "Properties not found for such PID."})
        return self.__respuesta.respuesta_prop("endpointprop","networkmap-default",self.__vtag, props)

    # Mover a un documento que sea de funciones qkd, y estas funciones serían importadas desde otro lugar.
    ### Ampliation functions
    def get_bordernode(self, node=None):
        if node != None:
            if node in self.bordernodes.keys():
                return self.bordernodes[node]
            else:
                for server in self.known_servers:
                    if (server[1] != self.puerto):# or (server[0] != self.ip):
                        response = self.ask_other_alto_server(node, server[0], server[1])
                        if response != {}:
                            #print("RESPUESTAAA:\t", str(response))
                            #datos = response.split('\n')
                            print("DATOS:\t", str(len(response)), response)
                             #.replace('\t', '').replace('\n', '').strip())
                            #print("DATOS:\t", type(response))
                            #datos = dict(dat)
                            for node in response["cost-maps"].keys():
                                if node in self.nodos:
                                    print("NODO:\t", node)
                                    return node                    
                            #print(response)
        return ""
    
    # Mover a un documento que sea de funciones qkd, y estas funciones serían importadas desde otro lugar.
    # Ver cómo esta función pueda servir también para una federación entre servidores ALTO.
    def ask_other_alto_server(self, pid, rip="127.0.0.1", rport=REMOTE_PORT):
        # Creamos un socket.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #print("Me cago en mi puta vida 2")
        # Definimos el mensaje HTTPS que debemos enviar. Primera versión es solamente HTTP.
        # Construir el cuerpo JSON
        #data = {"filter": "qkd", "pid": str(pid)}
        data = {"node": str(pid)}
        json_data = json.dumps(data)
        # Construir la solicitud HTTP POST
        #request = f"POST /costmap HTTP/1.1\r\nHost: alto-server\r\nContent-Type: application/json\r\nContent-Length: {len(json_data)}\r\n\r\n{json_data}"
        request = f"POST /costmap HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: {len(json_data)}\r\n\r\n{json_data}"
        # Establecemos conexión con el otro ALTO server.    
        try:
            server_address = (rip, rport)
            s.settimeout(3)
            #print("Petición al otro server:\t", str(request))
            s.connect(server_address)        
            s.sendall(request.encode())
            
            # Recibimos los datos.
            response = s.recv(8192)
            datos = response.decode()
            datos = str(datos.split("\r\n\r\n")[1]).replace('"',"").replace("'", '"').strip()
            print("DATOSSSSS:\t", datos)
            result = json.loads(datos)
            #print("Resultado:\t", str(result))
        except ConnectionError as e:
            print(f"Error de conexión: {e}")
            result = {}            
        finally:
            s.close()
        # Devolvemos los datos. Si hay error devolvemos un vacío dado que sería imposible alcanzar el destino.
        return result
    
    def shortest_path(self, a, b):
        '''
        Returns the shortest path between two nodes using the djikstras algoritm.
        Imput: nodes a and b.
        Output: list of nodes that conforms the path between a and b.
        '''
        try:
            return networkx.dijkstra_path(self.__topology, a, b)
        except networkx.exception.NetworkXNoPath as e:
            return []
        except Exception as e:
            print(e)
            return -1

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

    ### Discretion function. This function is being deployed under the umbrella of the Discretion project.
    def get_filtered_cost_map(self, filtro):
        if filtro == "qkd":
            topo = self.__topology.copy()
            print(str(topo.nodes), str(topo.edges))
            with open('./endpoints/qkd-properties.json','r') as archivo:
                qprop = json.load(archivo)
                #nodos = [ 'pid%d:%s' % (DEFAULT_ASN, self.get_hex_id(n["node"])) for n in qprop["nodes"]]
                nodos = [ n["node"] for n in qprop["nodes"]]
                eliminar = []
                #print(str(nodos), str(topo.nodes))
                for nodo in topo.nodes:
                    if nodo not in nodos:
                        eliminar.append(nodo)
                print(str(eliminar))
                for nodo in eliminar:
                    topo.remove_node(nodo)
                print(str(topo.nodes), str(topo.edges))
            return self.compute_costmap(topo)
        else:
            return -1
        
    ### Discretion function. This function is being deployed under the umbrella of the Discretion project.
    def get_filtered_network_map(self, filtro):
        if filtro == "qkd":
            netmap = self.compute_netmap(DEFAULT_ASN,self.__redes)
            with open('./endpoints/qkd-properties.json','r') as archivo:
                qprop = json.load(archivo)
                nodos = [ 'pid%d:%s' % (DEFAULT_ASN, self.get_hex_id(n["node"])) for n in qprop["nodes"]]
                # nodos = [ self.obtain_pid(n["node"]) for n in qprop["nodes"]]
                eliminar = []
                #print(str(nodos))
                #print(str(netmap.keys()))
                for n in netmap.keys():
                    if n not in nodos:
                        #print(str(n),str(nodos))
                        eliminar.append(n)
                for n in eliminar:
                    netmap.pop(n)    
            return str(netmap)
        else:
            return -1

    ###################################
    ###    Other auxiliar methods   ###
    ###################################

    # Crear un fichero de funcionalidades asociado a cada uno de los proyectos.
    # Cuando se cargue el código desde ese proyecto, se realizará con las funcionalidades asociadas.
    # Las funcionalidades que se estandaricen en RFQs pueden quedarse aquí, indicando tanto el proyecto como el RFQ.

    ### Desire6G function. This work is part of the contributions of TID tto the Desire6G project. GA: 
    def desire6g_graphs(self, data):
        '''
            This function returns a sub-graph (defined as two lists, nodes and edges) with all the components that satisfy the requested parameter.
            In the first version we are just working with latency.
            Args:
                Data: JSON with the next structure: { "filter": {"name":STR, "value":FLOAT}, "src-nodes": LIST(STRs)}
            Returns:
                Nodes: List of nodes (pid1:23456789).
                Edges: List of edges ((Node1,Node2,Weight)).
        '''

        try:
        #if True:
            nodos = data["src-nodes"].copy()
            ejes = []
            peso = data["filter"]["value"]
            #print(nodos)
            #topo_ejes = networkx.generate_edgelist(self.__topology)
            # Recorremos los nodos 
            for nodo in data["src-nodes"]:
                #ejes = ejes + [(u,v,d["weight"]) for (u,v,d) in self.__topology.edges(data=True) if ((d["weight"] <= peso) and (u == nodo or v == nodo))] #This line is to work just with neightbour nodes.
                self.__evaluate_graph(nodo,peso,ejes,nodos) 
            
            ejes = list(set(ejes))
            #nodos = list(set([a for (a,b,c) in ejes] + [b for (a,b,c) in ejes]))
            #print(str(self.VUELTAS))
            for i in range(len(nodos)):
                nodos[i] = ('pid%d:%s' % (DEFAULT_ASN, self.get_hex_id(nodos[i])))
            respuesta = str( {'nodes':nodos, 'edges':ejes} )
            #respuesta = str( {'nodes':nodos} )

            #print(respuesta)
            return respuesta
        except:
        #else:
            print("Formato incorrecto.")
            return "{}"
  
    ### Desire6G function. This work is part of the contributions of TID tto the Desire6G project. GA: 
    def __evaluate_graph(self, nodo, peso, ejes, nodos, iteracion=0):
        '''
        Auxiliar function used to archive the recursivity in the mision of the previous function. 
        The goal is to locate all the nodes and links that are separated from "nodo", "peso" distance or less.
        Imputs:
            nodo: node to be evaluated.
            peso: max distance to nodo.
            ejes: list of edges to be updated (pointer). Also used to avoid uneded updates.
            nodos: list of nodes to be updated (pointer). Also used to avoid uneded iterations.
        '''
        #print("Peso:", peso, "Iteración:", iteracion)
        #self.VUELTAS = self.VUELTAS + 1
        if peso > 0:
            topo_ejes = self.__topology.edges(data=True) 
            #print("Adios")
            for eje in topo_ejes: 
                #print(nodo,peso,str(eje))
                if ((eje not in ejes) and (eje[2]["weight"] <= peso) and (eje[0] == nodo)):
                    #print("sfdk",nodo,str(eje[0:2]))
                    ejes.append((eje[0],eje[1],eje[2]["weight"]))
                    if eje[1] not in nodos:
                        nodos.append(eje[1])
                        self.__evaluate_graph(eje[1], (peso-eje[2]["weight"]), ejes, nodos, iteracion+1)
                elif ((eje not in ejes) and (eje[2]["weight"] <= peso) and (eje[1] == nodo)):
                    #print("SFDK",nodo,str(eje[0:2]))
                    ejes.append((eje[0],eje[1],eje[2]["weight"]))
                    if eje[0] not in nodos:
                        nodos.append(eje[0])
                        self.__evaluate_graph(eje[0], (peso-eje[2]["weight"]), ejes, nodos, iteracion+1)
        
    ### Desire6G function. This work is part of the contributions of TID tto the Desire6G project. GA: 
    def desire_neighbours(self,data):
        '''
        In this function we do something similar to the desire_graph but just with neighbour nodes.
        It returns the nodes where the separation respect one or more of the received nodes is less than a received weight.
        In the first version we are just working with latency.
            Args:
                Data: JSON with the next structure: { "filter": {"name":STR, "value":FLOAT}, "src-nodes": LIST(STRs)}
            Returns:
                Nodes: List of nodes (pid1:23456789).
                Edges: List of edges ((Node1,Node2,Weight)).
        '''
        try:
        #if True:
            nodos = data["src-nodes"].copy()
            ejes = []
            peso = data["filter"]["value"]
            #topo_ejes = networkx.generate_edgelist(self.__topology)
            # Recorremos los nodos
            for nodo in nodos:
                ejes = ejes + [(u,v,d["weight"]) for (u,v,d) in self.__topology.edges(data=True) if ((d["weight"] <= peso) and (u == nodo or v == nodo))] #This line is to work just with neightbour nodes.

            nodos = list(set([a for (a,b,c) in ejes] + [b for (a,b,c) in ejes]))
            #print(str(self.VUELTAS))
            respuesta = str( {'nodes':nodos, 'edges':ejes} )
            #print(respuesta)
            return respuesta
        except:
        #else:
            print("Formato incorrecto.")
            return "{}"

    ### Discretion function. This function is being deployed under the umbrella of the Discretion project.
    def evaluate_qkd_endpoints(self, node):
        '''
        This funtion evaluates the SDN database with the information of the nodes with QKD capabilities. 
        It should read the nodes, their properties and filter the maps by these nodes.
        This function if you are trying to integrate the QKD identification with other metrics, this could be called from other get properties.
        In this first version it will be reading information from a static file that will follow the ETSI QKD 015 format. 
        Imput: node to be evaluated.
        Output: If the node is in the qkd-properties doc, return the "sd-qkd-node" properties.
        '''
        with open('./endpoints/qkd-properties.json','r') as archivo:
            qprop = json.load(archivo)
            for nodo in qprop["nodes"]:
                if node == nodo["node"]:
                    return str(nodo["sd-qkd-node"])
        
        return -1

    ### Discretion function. This function is being deployed under the umbrella of the Discretion project.
    def cifrar_pids(self, router, asn=DEFAULT_ASN):
        """Returns the hashed PID of the router passed as argument.
            If the PID was already mapped, it uses a dictionary to access to it.
        """
        tsn = self.__vtag
        rid = self.__get_hex_id(router) if not self.__check_is_hex(router) else router
        if rid not in self.__ts.keys():
            self.__ts[rid] = tsn
        else:
            tsn = self.__ts[rid]
        hash_r = hashlib.sha3_384((router + str(tsn)).encode())
        #return ('pid%d:%s:%d' % (asn, hash_r.hexdigest()[:32], tsn))
        return ('pid%d:%s' % (asn, hash_r.hexdigest()[:32]))    
    
    ### Discretion function. This function is being deployed under the umbrella of the Discretion project.
    def __is_client_net(self, pid):
        '''
            If there are at least one network with client connectivity, then it's a end-net.
        '''
        try:
            #print(" __is_client_net", pid)
            if pid in self.__net_map.keys():
                for net in self.__net_map[pid]["ipv4"]:
                    #print(net.split("/")[-1])
                    if int(net.split("/")[-1]) < 30:
                        return 1
        except:
            print("Error en la evaluación c del pid:", pid, self.__net_map)
        return 0

    ### Discretion function. This function is being deployed under the umbrella of the Discretion project.
    def __is_border_node(self, pid):
        '''
            If it's connected with at least 1 diferent AS node, then it's a border node.
        '''
        try:
            our_asn = int(pid.split(":",1)[0][3:])
            #print("__is_border_node", pid,our_asn)
            for net in self.__cost_map[pid].keys():
                asn = int(net.split(":",1)[0][3:])
                #print(asn)
                if asn != our_asn and self.__cost_map[pid][net] == 1:
                    return 1
        except:
            print("Error en la evaluación b del pid:", pid, self.__cost_map)
        return 0

    ### Discretion function. This function is being deployed under the umbrella of the Discretion project.
    def __filter_net_map(self, filter_id):
        '''
            in this first version, the only filter we will do is the securoty filter.
            In this case, we will evaluate the selected criteria. The nodes that fit
            will be included in the returned net map.
        '''
        filtrado ={}
        for pid in self.__net_map.keys():
            if self.__is_client_net(pid) or self.__is_border_node(pid):
                cpid  = self.obtain_pid(pid)                
                filtrado[cpid] = self.__net_map[pid]
        return filtrado
    
    ### Manager function
    def gestiona_info(self, fuente):
        if fuente in self.__d_modules.keys():
            self.__d_modules[fuente].manage_topology_updates()

    def mailbox(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('localhost',self.port_module))
        print("Waiting...")      
        while 1:
            topo = s.recv(16384)
            print("Received:" + str(len(topo)) + " Bytes")
            topo = topo.decode()
            #try:
            if 1:
                datos = json.loads(str(topo).replace('\t', '').replace('\n', '').strip())
                ejes = datos["data"]["costs-list"]
                nodos = datos["data"]["nodes-list"]
                self.__redes = datos["data"]["prefixes"]
                #print(str(self.__redes))
                for nodo in nodos:
                    self.__topology.add_node(nodo)
                for eje in ejes:
                    #print(eje)
                    leje = eval(eje.replace("(","[").replace(")","]"))
                    self.__topology.add_edge(leje[0], leje[1], weight=leje[2])
                self.__vtag = str(int(datetime.now().timestamp()*1e6))
                print(self.__vtag)
                self.__net_map = self.compute_netmap(DEFAULT_ASN, self.__redes)
                self.__cost_map = self.compute_costmap(self.__topology)
                #print(datos["data"]["pids"])
                #self.compute_netmap()
                #self.__pids = datos["data"]["pids"]
                #print("Todo correcto Hulio")
                #self.comput-e_netmap(int(asn), pids)
            else:
            #except:
                print("Error al procesar:\n", str(topo))
            #print("netmap:\t" + str(datos["data"]["pids"]).replace("'",'"'))
            #print("costmap:\t" + str(self.__cost_map).replace("'",'"'))
            #print(str(self.desire6g_graphs({"filter":{"name":"latency","value":20},"src-nodes":["1.1.1.1","2.2.2.2"]})))

        self.http.detener()

    def evaluate_endpoints(self):
        with open('./endpoints/properties.json', 'r') as source:
            jason = source.read()
            jason = jason.replace('\t', '').replace('\n', '').replace("'", '"').strip()
            users = json.loads(str(jason))
            for user in users["users"]:
                user["pid"] = self.compute_pid_endpoint(user["ipv4"][0])
                #user["pid"] = ''
                #print(str(user))
                self.__endpoints[user["ipv4"][0]]=user


class TopologyFileWriter:

    def __init__(self, output_path):
        self.__output_path = output_path
        self.__pid_file = 'pid_file.json'
        self.__cost_map_file = 'cost_map.json'
        self.__same_node_ips = "router_ids.json"

    def write_file(self, file_name, content_to_write):
        """Writes file_name in output_file"""
        full_path = os.path.join(self.__output_path, file_name)
        with open(full_path, 'w') as out_file:
            json.dump(content_to_write, out_file, indent=4)

    def write_pid_file(self, content):
        self.write_file(self.__pid_file, content)

    def write_cost_map(self, content):
        self.write_file(self.__cost_map_file, content)

    def write_same_ips(self, content):
        self.write_file(self.__same_node_ips, content)


### Aux clases ###
class TopologyUpdateThread(threading.Thread):

    def __init__(self, topo_manager):
        threading.Thread.__init__(self)
        self.__tp_mng = topo_manager

    def run (self):
        t,a,p,c = self.__tp_mng.manage_bgp_speaker_updates()
        return t,a,p,c

### Aux clases ###
class TopologyExpoThread(threading.Thread):

    def __init__(self, a):
        threading.Thread.__init__(self)
        self.__api = AltoHttp(a)

    def run (self):
        self.__api.run()





if __name__ == '__main__':
    '''speaker_bgp = ManageBGPSpeaker()
    exabgp_process = speaker_bgp.check_tcp_connection()
    
    topology_creator = TopologyCreator(exabgp_process,0)
    topology_creator.manage_ietf_speaker_updates()
    '''
    
    ## Necesita depuración.
    
    
    mode = 0
    modules = {}
    with open("config.yaml", "r") as stream:
        try:
            doc  = yaml.safe_load(stream)
            
            #Cargamos los parámetros de los módulos
            if "MODULES_IP" in doc.keys():
                ipm = doc["MODULES_IP"]
            else:
                ipm = "127.0.0.1"
            if "MODULES_PORT" in doc.keys():
                portm = doc["MODULES_PORT"]
            else:
                portm = 5001    
            #Cargamos los módulos
            if "MODULES" in doc.keys():
                if "BGP" in doc["MODULES"]:
                    modules["bgp"] = TopologyBGP((ipm,portm))
                if "IETF" in doc["MODULES"]:
                    modules['ietf'] = TopologyIetf((ipm,portm))
                if "ALTO" in doc["MODULES"]:
                    modules['alto'] = TopologyAlto((ipm,portm), "./maps/")
                if "QKD" in doc["MODULES"]:
                    modules['qkd'] = TopologyQKD((ipm,portm), "./maps/")
                        
            # Una vez comprobados todos los módulos, tenemos que asegurar que por lo menos haya uno. 
            # Módulo por defecto: BGP
            if len(modules.keys()) == 0:
                modules["bgp"] = TopologyBGP((ipm,portm))
    
            # Cargamos los parámetros de las APIs
            if "API_PORT" in doc.keys():
                DEF_PORT = doc["API_PORT"]
            if "API_IP" in doc.keys():
                ipa = doc["API_IP"]
            else:
                ipa = "127.0.0.1"
                
            if "API" in doc.keys():
                if "KAFKA" in doc["API"]:   
                    mode = 1
            
        except yaml.YAMLError as exc:
            print("No se ha podido cargar el documento. Error: ", exc)
            modules={}
            #modules['bgp'] = TopologyBGP(('localhost',8081))
            modules['ietf'] = TopologyIetf(('localhost',"5000"))


    print("Creando ALTO CORE")
    alto = TopologyCreator(modules, mode, DEF_IP, DEF_PORT, portm)
    threads = list()
    for modulo in modules.keys():
        print("Creando el módulo de topología:",modulo)
        x = threading.Thread(target=alto.gestiona_info, args=(modulo,))#, daemon=True)
        threads.append(x)
        x.start()    
        
        
        
        
        print("Lanzando API REST")
        t_api = threading.Thread(target=alto.run_api)
        t_api.start()
                #alto.launch_api()
                
                
    print("Lanzando gestor de respuestas")
    alto.mailbox()


