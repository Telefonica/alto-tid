#!/usr/bin/env python3
# © 2024 Telefónica Innovación Digital, All rights reserved

# Main imports
import time
import ipaddress
import os
import json
import re
import struct
import socket
import threading
import hashlib
import ast
from datetime import datetime

#External imports
import networkx
from networkx.readwrite import json_graph
import requests

# from modulos.topology_bgp import TopologyBGP
# from modulos.topology_ietf import TopologyIetf
# Own imports
from modulos.topology_qkd import TopologyQKD
from yang_alto import RespuestasAlto
from api.web.alto_http import AltoHttp
from alto_logger import AltoLogger
# from api.web.federation import FederationApi

DEFAULT_ASN = 0
DEF_PORT = 8888
REMOTE_PORT = 8888
DEF_IP = "127.0.0.1"
ERRORES = { "sintax" : "E_SYNTAX", "campo" : "E_MISSING_FIELD",
           "tipo" : "E_INVALID_FIELD_TYPE", "valor" : "E_INVALID_FIELD_VALUE" }
class TopologyCreator:
    ''' Class to integrate all the capabilities for the ALTO server.'''
    def __init__(self, module_data, ip="127.0.0.1", puerto=8888,
                         module_port=5000, servers=None):
        if servers is None:
            servers = [["192.168.159.83", 8080]]
        self.__d_modules = module_data
        self.__redes = []
        self.topology = networkx.Graph()
        self.__cost_map = {}
        self.__net_map = {}
        self.nodos = []
        self.bordernodes = {}
        self.ip = ip
        self.ts = {}
        self.__endpoints = {}
        self.known_servers = servers
        self.remotes = {}
        for server in self.known_servers:
            self.remotes[server[0]] = networkx.Graph()
        self.puerto = puerto
        self.port_module = module_port
        self.api = AltoHttp(self, ip, puerto)
        self.gui_app = self.api.app
        self.__vtag = 0
        self.__respuesta = RespuestasAlto()
        self.polling_interval = 60  # segundos
        self.start_remote_polling()
        self.logger = AltoLogger("log/alto")



    def costmap_to_node_link(self, data):
        ''' Convertir un diccionario de costmap a un formato node-link para NetworkX. '''
        costmap = data.get('cost-map', {})
        g = networkx.Graph()

        for src, targets in costmap.items():
            g.add_node(src)  # asegúrate de agregar el nodo incluso si no tiene edges
            for dst, weight in targets.items():
                if not g.has_edge(src, dst):  # evitar duplicados
                    g.add_edge(src, dst, weight=weight)

        # Convertir a formato node-link (JSON serializable)
        return json_graph.node_link_data(g)


    def fetch_remote_topology(self, server):
        ''' Fetch remote topology from a given server. '''
        try:
            url = f"http://{server[0]}:{server[1]}/costmap"
            response = requests.get(url, timeout=5)

            if response.status_code == 200:
                try:
                    s_data = response.json()
                    data = json.loads(s_data.replace("'", '"'))
                    print("Hola 1")
                except ValueError:
                    # Si no es JSON válido, intentar decodificar desde string crudo
                    raw_text = response.text.strip()
                    print("Hola 2")
                    # Reemplaza comillas simples por dobles, escapando adecuadamente
                    safe_text = re.sub(r"'", '"', raw_text)
                    try:
                        data = json.loads(safe_text.replace("'", '"'))
                        print("Hola 3")
                    except json.JSONDecodeError as e:
                        print("Hola 4")
                        print(f"[ERROR] No se pudo decodificar como \
                              JSON ni desde texto en {server}: {e}")
                        print(f"[DEBUG] Texto recibido:\n{raw_text}")
                        return
                print("[INFO] Datos obtenidos de la topología remota:", data)
                if isinstance(data, dict):
                    try:
                        print("Hola 5")
                        data_node_link = self.costmap_to_node_link(data)
                        graph = networkx.node_link_graph(data_node_link)
                        self.remotes[server[0]] = graph
                        print(f"[INFO] Topología actualizada desde {server}")
                    except Exception as e:
                        print(f"[ERROR] Fallo al convertir JSON a grafo desde {server}: {e}")
                else:
                    print(f"[WARN] Datos no válidos desde {server}: no es un diccionario JSON")
            else:
                print(f"[WARN] Fallo al obtener topología de {server}, \
                      status: {response.status_code}")
        except requests.RequestException as e:
            print(f"[ERROR] Error al contactar con {server}: {e}")

    def poll_remotes(self):
        ''' Poll remote servers for topology updates. '''
        while True:
            for server in self.known_servers:
                self.fetch_remote_topology(server)
            time.sleep(self.polling_interval)

    def start_remote_polling(self):
        ''' Start a thread to poll remote servers. '''
        thread = threading.Thread(target=self.poll_remotes, daemon=True)
        thread.start()


    ######################
    ### Static Methods ###
    ######################

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
        '''Check if a string is a valid hexadecimal number.'''
        try:
            int(hex_value, 16)
            return True
        except ValueError:
            return False

    @staticmethod
    def check_if_router_id_is_hex(router_id):
        '''Check if a router ID is in hexadecimal format.'''
        return router_id.isnumeric()

    @staticmethod
    def reverse_ip(reversed_ip):
        '''Convert a reversed IP address to standard format.'''
        l = reversed_ip.split(".")
        return '.'.join(l[::-1])

    @staticmethod
    def hex_to_ip(hex_ip):
        """Convert a hexadecimal string to an IP address."""
        hex_ip = hex_ip.strip("0")
        addr_long = int(hex_ip, 16) & 0xFFFFFFFF
        struct.pack("<L", addr_long)
        return socket.inet_ntoa(struct.pack("<L", addr_long))



    ######################
    ### Public methods ###
    ######################

    def get_router_id(self, value):
        '''Convert a router ID to its standard IP format.'''
        if self.check_if_router_id_is_hex(value):
            return self.split_router_ids(value)
        elif "." in value:
            return value
        else:
            return self.reverse_ip(self.hex_to_ip(value))

    def run_api(self):
        ''' Run the API server. '''
        self.api.run()

    def parseo_yang(self, mensaje, tipo):
        '''
        It creates a message in the format expected by the ALTO client just as the RFC defined.
        Under evaluation for Stage 2.0.
        Imputs:
            mensaje: Map to be sent.
            tipo: type of map sent.
        Output: formated message with some metadata.
        '''
        return str(tipo) + 'json{"alto-tid":"1.0","time":' +  \
            str(datetime.timestamp(datetime.now())) + ',"host":"altoserver-alberto","' + \
                str(tipo) + '":' + str(mensaje) + '},}'

    def compute_netmap(self, asn, redes):
        '''
        This funtion evaluates the list of networks founded and associates them to the node
        in the topology that enroutes it.
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
            pid = self.obtain_pid(router)
            if ipv4:
                if pid not in net_map:
                    net_map[pid] = {}
                net_map[pid]['ipv4'] = ipv4
            if ipv6:
                net_map[pid]["ipv6"] = ipv6
        return net_map

    def compute_costmap(self, topo=None):
        '''This funtion evaluates the topology and computes the cost map.'''
        # shortest_paths is a dict by source and target that contains the shortest path length for
        # that source and destination
        if topo is not None:
            topo = self.topology
        cost_map = {}
        shortest_paths = dict(networkx.shortest_paths.all_pairs_dijkstra_path_length(topo))
        for src, dest_pids in shortest_paths.items():

            src_pid_name = src
            for dest_pid, weight in dest_pids.items():

                dst_pid_name = dest_pid
                if src_pid_name in self.nodos:
                    if src_pid_name not in cost_map:
                        cost_map[src_pid_name] = {}
                    cost_map[src_pid_name][dst_pid_name] = weight

        return cost_map

    def obtain_pid(self, router):
        """Returns the hashed PID of the router passed as argument.
            If the PID was already mapped, it uses a dictionary to access to it.
        """
        tsn = int(datetime.timestamp(datetime.now())*1000000)
        if len(router.split(":")) > 1:
            router = router.split(":")[1]
        rid = self.get_hex_id(router) if not self.check_is_hex(router) else router
        if rid not in self.ts:
            self.ts[rid] = tsn
        else:
            tsn = self.ts[rid]
        hash_r = hashlib.sha3_384((router + str(tsn)).encode())
        return ('pid%d:%s:%d' % (DEFAULT_ASN, hash_r.hexdigest()[:32], tsn))

    def compute_pid_endpoint(self, endpoint):
        """Returns the PID of the endpoint passed as argument.
            If the PID was already mapped, it uses a dictionary to access to it.
        """
        #Vamos a recibir la IP del
        ip_e = ipaddress.IPv4Address(endpoint)
        red = "0.0.0.0/-1"
        pid_e = 0
        #print(str( self.__net_map))
        for pid in self.__net_map.items():
            #print("pid", pid)
            for prefijo in self.__net_map[pid]["ipv4"]:
                if ip_e in ipaddress.IPv4Network(prefijo):
                    if int(prefijo.split("/")[1]) > int(red.split("/")[1]):
                        red = prefijo
                        pid_e = pid
        #print(endpoint,self.__net_map[pid_e]["ipv4"])
        return pid_e

    def launch_api(self):
        ''' Launch the API server. '''
        t_http = threading.Thread(target=self.api.run)
        t_http.start()



   ##############################################
   ###    Functions to be called by the API   ###
   ##############################################

    ### RFC7285 functions
    def get_costs_map_by_pid(self, pid):
        '''Get the cost map by PID.'''
        #pid = "pid0:" + str(npid)
        #print(pid)
        #print(str(self.__pids))
        if not pid:
            return str({"ERROR" : ERRORES["campo"], "syntax-error": "Missing PID."})
        if not isinstance(pid, str):
            return str({"ERROR" : ERRORES["tipo"],
                        "syntax-error": "The PID type is incorrect. We need a string."})
        if pid in self.__cost_map:
            #print(str(self.__pids))
            #print(str(self.__cost_map))
            mapa = self.__cost_map[pid]
            return self.__respuesta.crear_respuesta("cost-map", "costmapfilter",
                                                "my-default-network-map", self.__vtag, str(mapa))
        else:
            for server in self.known_servers:
                if server[1] != self.puerto:# or (server[0] != self.ip):
                    response = self.ask_other_alto_server(pid, server[0], server[1])
                    if response != "":
                        return response

            return str({"ERROR" : ERRORES["valor"], "syntax-error": "PID not found."})

    def get_properties(self, pid, properties=None):
        '''Get the properties of a given PID.'''
        #return str(self.bf.session.q.nodeProperties().answer().frame())
        #pid = self.__compute_pid_endpoint(endpoint)
        resp = {}
        if pid:
            if not isinstance(pid, str):
                return str({"ERROR" : ERRORES["tipo"],
                            "syntax-error": "The PID type is incorrect. We need a string."})
            #if pid not in self.topology.nodes():
            #    return str({"ERROR" : ERRORES["valor"], "syntax-error": "PID not found."})
            if properties:
                if not isinstance(properties, str):
                    return str({"ERROR" : ERRORES["tipo"],
                                "syntax-error": "Incorrect property type. We need a string."})
                with open('./endpoints/properties.json','r', encoding='utf-8') as archivo:
                    prop = json.load(archivo)
                    for usuario in prop["users"]:
                        result = {}
                        if usuario["ipv4"][0] == pid:
                            for propiedad in properties:
                                if propiedad in usuario["properties"].keys():
                                    result[propiedad] = usuario["properties"][propiedad]
                            if result:
                                for prop in properties:
                                    resp = {"ipv4": pid ,"properties": properties,
                                            "values": [result[prop] for prop in properties]}
                            else:
                                return str({"ERROR" : ERRORES["valor"],
                                            "syntax-error": f'{properties} not valid for {pid}'})
                return self.__respuesta.respuesta_prop("endpointprop",
                                            "my-default-network-map.prop", self.__vtag, str(resp))
            else:
                with open('./endpoints/properties.json','r', encoding='utf-8') as archivo:
                    prop = json.load(archivo)
                    for usuario in prop["users"]:
                        result = {}
                        if usuario["ipv4"][0] == pid:
                            resp = usuario
                            return self.__respuesta.respuesta_prop("endpointprop",
                                        "my-default-network-map.prop", self.__vtag, str(resp))
                #print(resp)
            #else:
        #return str(self.bf.session.q.nodeProperties().answer().frame())
        return str({"ERROR" : ERRORES["campo"], "syntax-error": "PID not provided"})

    def get_endpoint_costs(self, endpoint):
        '''Get the costs map for a given endpoint.'''
        pid = self.__endpoints.get(endpoint)
        if pid:
            return self.get_costs_map_by_pid(pid["pid"])
        return str({"ERROR" : ERRORES["valor"], "syntax-error": "Endpoint not found."})
        #return "Implementation in proccess. Sorry dude"

    def get_maps(self, filtro=None):
        '''Get the network and costs maps.'''
        if filtro is not None:
            return '{"network_map":' + self.get_net_map() + \
                    ', "costs_map":' + self.get_costs_map() + '}'
        return '{"network_map":' + self.get_net_map(filtro) + \
                    ', "costs_map":' + self.get_costs_map(filtro) + '}'

    def get_costs_map(self, filtro=None):
        '''Get the costs map.'''
        if filtro is not None:
            return self.__respuesta.respuesta_costes("costmap",
                                        "networkmap-default", self.__vtag, str(self.__cost_map))
        else:
            f_costmap = self.get_filtered_cost_map(filtro)
            if f_costmap == -1:
                return str({"ERROR" : ERRORES["campo"], "syntax-error": "Filter not valid."})
            return self.__respuesta.respuesta_costes("costmapfilter",
                                                     "networkmap-default", self.__vtag, f_costmap)

    def get_net_map(self, filtro=None):
        '''Get the network map.'''
        if filtro is not None:
            return self.__respuesta.respuesta_pid("networkmap",
                                        "networkmap-default", self.__vtag, str(self.__net_map))
        else:
            f_netmap = self.get_filtered_network_map(filtro)
            if f_netmap == -1:
                return str({"ERROR" : ERRORES["campo"], "syntax-error": "Filter not valid."})
            return self.__respuesta.respuesta_pid("networkmapfilter",
                                                  "networkmap-default",self.__vtag, f_netmap)

    def get_directory(self):
        '''Get the directory of the ALTO server.'''
        return self.__respuesta.indice()

    def get_qkd_properties(self, node=None):
        '''Get the properties of a given QKD node.'''
        if node is None:
            return str({"ERROR" : ERRORES["valor"], "syntax-error": "Null Link-ID is not valid."})
        if not isinstance(node, str):
            return str({"ERROR" : ERRORES["tipo"],
                        "syntax-error": "The PID type is incorrect. We need a string."})
        if len(node.split(":"))>0:
            nnode = self.reverse_ip(self.hex_to_ip(node.split(":")[1]))
            mensaje = f"Node received: {nnode}"
            self.logger.log_message(mensaje)
        else:
            nnode = self.reverse_ip(self.hex_to_ip(node))
            mensaje = f"Node received: {nnode}"
            self.logger.log_message(mensaje)
        props = self.evaluate_qkd_endpoints(nnode)
        if props == -1:
            return str({"ERROR" : ERRORES["valor"],
                        "syntax-error": "Properties not found for such PID."})
        return self.__respuesta.respuesta_prop("endpointprop",
                                               "networkmap-default",self.__vtag, props)


    def get_qkd_link_properties(self, link=None):
        '''Get the properties of a given QKD link.'''
        if link is None:
            return str({"ERROR" : ERRORES["valor"], "syntax-error": "Link-ID ."})
        if not isinstance(link, str):
            return str({"ERROR" : ERRORES["tipo"],
                        "syntax-error": "The Link-ID type is incorrect. We need a string."})
        qkdl_remote = self.__get_qlink_information(link)
        if qkdl_remote == {}:
            return str({"ERROR" : ERRORES["valor"], "syntax-error": "Link-ID not found."})
        return self.__respuesta.respuesta_prop("endpointprop",
                                               "networkmap-default",self.__vtag, qkdl_remote)

    def __get_qlink_information(self, link):
        '''Get the properties of a given QKD link.'''
        with open('./endpoints/qkd-nodes.json','r', encoding='utf-8') as archivo:
            qprop = json.load(archivo)
            for node in qprop["qkd_nodes"]:
                for qlink in node["qkd_node"]["qkd_links"]["qkd_link"]:
                    if qlink["qkdl_id"] == link:
                        return qlink["qkdl_remote"]
        return {}

    def longest_path_min_weight(self, source, target):
        '''Calculate the longest path with minimum weight between two nodes.'''
        # Generate all simple paths from source to target
        all_paths = list(networkx.all_simple_paths(self.topology, source=source, target=target))
        # print("ALL paths:\t", all_paths)
        # If no paths exist, return None
        if not all_paths:
            return None

        # Calculate the weight of each path as the minimum edge weight in the path
        path_weights = []
        for path in all_paths:
            min_weight = 99999999
            for i in range(len(path) - 1):
                u = path[i]
                v = path[i + 1]
                edge_weight = self.topology[u][v]['weight']
                # print("Edge weight:\t", edge_weight)
                if edge_weight < min_weight:
                    min_weight = edge_weight
            if min_weight == 99999999:
                min_weight = -1
            path_weights.append(min_weight)

        # Return the maximum weight among all paths
        return max(path_weights)

    def get_remote_nodes(self, server):
        """
        Realiza una solicitud HTTP a una dirección IP y puerto dados con un endpoint específico.

        :param ip: Dirección IP como cadena (str)
        :param puerto: Puerto como entero (int)
        :param endpoint: Endpoint como cadena (str)
        :return: Respuesta en formato JSON como diccionario
        :raises: requests.exceptions.RequestException si hay algún error en la solicitud
        """
        # Construir la URL
        url = f"http://{server[0]}:{server[1]}/costmap"

        try:
            # Realizar la solicitud GET
            respuesta = requests.get(url)

            # Verificar si la solicitud fue exitosa
            respuesta.raise_for_status()

            # Intentar convertir la respuesta a JSON
            return json.loads(respuesta.json().replace("'", '"'))

        except requests.exceptions.RequestException as error:
            print(f"Error al realizar la solicitud: {error}")
            return None

    ### Ampliation functions
    def get_bordernode(self, node=None, source="cccccccc-cccc-cccc-cccc-cccccccccccc"):
        '''This function is used to get the border node of a given node.'''
        # print("\n\n\n\n\n")
        node_local = ""
        node_remote = ""
        optimal = -1
        try:
        # if 1:
            if node is not None:
                mensaje = f"\nNode:\t{node}\nREMOTES:\t{self.bordernodes.keys()}"
                self.logger.log_message(mensaje)
                for remote in self.bordernodes.items():
                    for local in self.bordernodes[remote].items():
                        #peso = self.longest_path_min_weight(source, remote)
                        peso_remote = self.bordernodes[remote][local]["weight"]
                        # peso = peso_remote
                        if peso_remote > optimal:
                            optimal = peso_remote
                            node_local = local
                            node_remote  = remote
                if node_local:
                    self.logger.log_message(f"Local node: {node_local}\t \
                                            Remote Node: {node_remote}")
                    return str({"local": {"qkdn_id": node_local,
                        "qkdi_id": self.bordernodes[node_remote][node_local]["local_id"]},
                        "remote": {"qkdn_id": node_remote,
                        "qkdi_id": self.bordernodes[node_remote][node_local]["remote_id"]}})
        except Exception as e:
            print("ERROR:\t", e)
        return str({"ERROR" : ERRORES["valor"], "syntax-error": "Remote PID not found."})

    def peso_remoto(self, bnode, node):
        '''This function is used to get the cost of a given node.'''
        peso = -2
        for server in self.known_servers:
            try:
                response = self.ask_other_alto_server(node, server[0], server[1])
                if response != {}:
                    # print("DATOS peso remoto:\t", response)
                    if bnode in response["cost-map"].keys():
                        peso = response["cost-map"][bnode]
            except Exception as e:
                print("Connection refused.")
                print("Error:\t", e)
                continue
        return peso

    ### Ampliation functions
    def old_get_bordernode(self, node=None):
        '''This function is used to get the border node of a given node.'''
        # print("NODE:\t", node)
        if node is not None:
            for server in self.known_servers:
                try:
                    # if ((server[1] != self.puerto) or (server[0] != self.ip)):
                    response = self.ask_other_alto_server(node, server[0], server[1])
                    if response != {}:
                        for node2 in response["cost-map"].keys():
                            if node2 in self.nodos:
                                # print("NODO:\t", node2)
                                # Potential Optimization problem.
                                # Ussing By default: remote node will be the first one saved.
                                # Just one Connection between networks.
                                for node3 in self.bordernodes.items():
                                    if self.bordernodes[node3]["node"] == node2:
                                        return str({"local": {"qkdn_id": self.bordernodes[node3]["node"], "qkdi_id": self.bordernodes[node3]["local_id"]},
                                                    "remote": {"qkdn_id": node3, "qkdi_id": self.bordernodes[node3]["remote_id"]}})
                                        #return str({"border-node":node2, "remote" : node3})
                        #print(response)
                except Exception as e:
                    print(f"Error de conexión: {e}")
                    continue
        return str({"ERROR" : ERRORES["valor"], "syntax-error": "Remote PID not found."})

    def ask_other_alto_server(self, pid, rip="127.0.0.1", rport=REMOTE_PORT):
        '''This function is used to ask the other ALTO server for the cost map.'''
        # Creamos un socket.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #print("Me cago en mi puta vida 2")
        # Definimos el mensaje HTTPS que debemos enviar. Primera versión es solamente HTTP.
        # Construir el cuerpo JSON
        #data = {"filter": "qkd", "pid": str(pid)}
        data = {"node": str(pid)}
        json_data = json.dumps(data)
        # Construir la solicitud HTTP POST
        request = f"POST /costmap HTTP/1.0\r\nContent-Type: application/json\r\n \
        Content-Length: {len(json_data)}\r\n\r\n{json_data}"
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
            #print("DATOSSSSS:\t", datos)
            result = json.loads(datos)
            #print("Resultado:\t", str(result))
        except ConnectionError as e:
            print(f"Connection error: {e}")
            result = {}
        finally:
            s.close()
        # Devolvemos los datos.
        # Si hay error devolvemos un vacío dado que sería imposible alcanzar el destino.
        return result

    def shortest_path(self, a, b):
        '''
        Returns the shortest path between two nodes using the djikstras algoritm.
        Imput: nodes a and b.
        Output: list of nodes that conforms the path between a and b.
        '''
        try:
            return networkx.dijkstra_path(self.topology, a, b)
        except networkx.exception.NetworkXNoPath as e:
            print(f"[ERROR] No path found between {a} and {b}: {e}")
            return []
        except Exception as e:
            print(e)
            return -1

    def all_maps(self, topo, src, dst):
        '''
        Returns all the diferent paths between src and dest without any edge in common.
        The result is a list of paths (each path is represented as a char list,
        e.g. ['a', 'c', 'd'])
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
                print(f"[ERROR] No path found between {src} and {dst}: {e}")
                sh_path = []
        return all_paths

    ### Discretion function.
    # This function is being deployed under the umbrella of the Discretion project.
    def get_filtered_cost_map(self, filtro):
        '''This function is used to filter the cost map by a given filter.'''
        if filtro == "qkd":
            topo = self.topology.copy()
            # print(str(topo.nodes), str(topo.edges))
            with open('./endpoints/qkd-properties.json', 'r', encoding='utf-8') as archivo:
                qprop = json.load(archivo)
                nodos = [ n["node"] for n in qprop["nodes"]]
                eliminar = []
                #print(str(nodos), str(topo.nodes))
                for nodo in topo.nodes:
                    if nodo not in nodos:
                        eliminar.append(nodo)
                # print(str(eliminar))
                for nodo in eliminar:
                    topo.remove_node(nodo)
                # print(str(topo.nodes), str(topo.edges))
            return self.compute_costmap(topo)
        else:
            return -1

    ### Discretion function.
    # This function is being deployed under the umbrella of the Discretion project.
    def get_filtered_network_map(self, filtro):
        '''This function is used to filter the network map by a given filter.'''
        if filtro == "qkd":
            netmap = self.compute_netmap(DEFAULT_ASN,self.__redes)
            with open('./endpoints/qkd-properties.json','r', encoding='utf-8') as archivo:
                qprop = json.load(archivo)
                nodos = [ 'pid%d:%s' % (DEFAULT_ASN, self.get_hex_id(n["node"])) \
                    for n in qprop["nodes"]]
                # nodos = [ self.obtain_pid(n["node"]) for n in qprop["nodes"]]
                eliminar = []
                #print(str(nodos))
                #print(str(netmap.keys()))
                for n in netmap.items():
                    if n not in nodos:
                        #print(str(n),str(nodos))
                        eliminar.append(n)
                for n in eliminar:
                    netmap.pop(n)
            return str(netmap)
        else:
            return -1

    ### Discretion function.
    # This function is being deployed under the umbrella of the Discretion project.
    def evaluate_qkd_endpoints(self, node):
        '''
        This funtion evaluates the SDN database with the information of the nodes with
        QKD capabilities.
        It should read the nodes, their properties and filter the maps by these nodes.
        This function if you are trying to integrate the QKD identification with other metrics,
        this could be called from other get properties.
        In this first version it will be reading information from a static file that will follow
        the ETSI QKD 015 format.
        Imput: node to be evaluated.
        Output: If the node is in the qkd-properties doc, return the "sd-qkd-node" properties.
        '''
        with open('./endpoints/qkd-properties.json','r', encoding='utf-8') as archivo:
            qprop = json.load(archivo)
            for nodo in qprop["nodes"]:
                if node == nodo["node"]:
                    return str(nodo["sd-qkd-node"])
        return -1

    ### Discretion function.
    # This function is being deployed under the umbrella of the Discretion project.
    def cifrar_pids(self, router, asn=DEFAULT_ASN):
        """Returns the hashed PID of the router passed as argument.
            If the PID was already mapped, it uses a dictionary to access to it.
        """
        tsn = self.__vtag
        rid = self.get_hex_id(router) if not self.check_is_hex(router) else router
        if rid not in self.ts.items():
            self.ts[rid] = tsn
        else:
            tsn = self.ts[rid]
        hash_r = hashlib.sha3_384((router + str(tsn)).encode())
        #return ('pid%d:%s:%d' % (asn, hash_r.hexdigest()[:32], tsn))
        return ('pid%d:%s' % (asn, hash_r.hexdigest()[:32]))

    ### Discretion function.
    # This function is being deployed under the umbrella of the Discretion project.
    def __is_client_net(self, pid):
        '''
            If there are at least one network with client connectivity, then it's a end-net.
        '''
        try:
            #print(" __is_client_net", pid)
            if pid in self.__net_map.items():
                for net in self.__net_map[pid]["ipv4"]:
                    #print(net.split("/")[-1])
                    if int(net.split("/")[-1]) < 30:
                        return 1
        except Exception as e:
            print("Error en la evaluación c del pid:", pid, self.__net_map)
            print("Error:\t" , e)
        return 0

    ### Discretion function.
    # This function is being deployed under the umbrella of the Discretion project.
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
        except  Exception as e:
            print("Error en la evaluación b del pid:", pid, self.__cost_map)
            print("Error:\t", e)
        return 0

    ### Discretion function.
    # This function is being deployed under the umbrella of the Discretion project.
    def __filter_net_map(self, filter_id):
        '''
            in this first version, the only filter we will do is the securoty filter.
            In this case, we will evaluate the selected criteria. The nodes that fit
            will be included in the returned net map.
        '''
        filtrado ={}
        for pid in self.__net_map.items():
            if self.__is_client_net(pid) or self.__is_border_node(pid):
                cpid  = self.obtain_pid(pid)
                filtrado[cpid] = self.__net_map[pid]
        return filtrado

    ### Manager function
    def gestiona_info(self, fuente):
        '''This function is used to manage the information of the given module.'''
        if fuente in self.__d_modules.keys():
            self.__d_modules[fuente].manage_topology_updates()

    def mailbox(self):
        '''This function is used to manage the mailbox of the given module.'''
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('localhost',self.port_module))
        self.logger.log_message("Waiting...")
        while 1:
            topo = s.recv(16384)
            mensaje = f"Received: {str(len(topo))} Bytes"
            self.logger.log_message(mensaje)
            topo = topo.decode()
            # if 1:
            try:
                datos = json.loads(str(topo).replace('\t', '').replace('\n', '').strip())
                ejes = datos["data"]["costs-list"]
                self.nodos = datos["data"]["nodes-list"]
                self.apis = datos["data"]["prefixes"]

                for nodo in self.nodos:
                    self.topology.add_node(nodo)
                    self.topology.nodes[nodo]["type"] = "local"
                for eje in ejes:
                    leje = ast.literal_eval(eje.replace("(", "[").replace(")", "]"))
                    self.topology.add_edge(leje[0], leje[1], weight=leje[2])
                    if leje[1] not in self.nodos:
                        if leje[1] not in self.bordernodes:
                            self.bordernodes[leje[1]] = {}
                        self.bordernodes[leje[1]][leje[0]]={"local_id":self.apis[leje[0]][leje[1]],
                                        "remote_id":self.apis[leje[1]][leje[0]], "weight":leje[2]}
                self.__vtag = str(int(datetime.now().timestamp()*1e6))

                self.__cost_map = self.compute_costmap(self.topology)
            except Exception:
                print("Error during processing code:\n", str(topo))

        self.api.detener()

    def evaluate_endpoints(self):
        '''This function is used to evaluate the endpoints of the given module.'''
        with open('./endpoints/properties.json', 'r', encoding='utf-8') as source:
            jason = source.read()
            jason = jason.replace('\t', '').replace('\n', '').replace("'", '"').strip()
            users = json.loads(str(jason))
            for user in users["users"]:
                user["pid"] = self.compute_pid_endpoint(user["ipv4"][0])
                #user["pid"] = ''
                #print(str(user))
                self.__endpoints[user["ipv4"][0]]=user


class TopologyFileWriter:
    '''Class to write files in the output path'''

    def __init__(self, output_path):
        self.__output_path = output_path
        self.__pid_file = 'pid_file.json'
        self.__cost_map_file = 'cost_map.json'
        self.__same_node_ips = "router_ids.json"

    def write_file(self, file_name, content_to_write):
        """Writes file_name in output_file"""
        full_path = os.path.join(self.__output_path, file_name)
        with open(full_path, 'w', encoding='utf-8') as out_file:
            json.dump(content_to_write, out_file, indent=4)

    def write_pid_file(self, content):
        """Writes the pid file in the output path"""
        self.write_file(self.__pid_file, content)

    def write_cost_map(self, content):
        """Writes the cost map file in the output path"""
        self.write_file(self.__cost_map_file, content)

    def write_same_ips(self, content):
        """Writes the same node IPs file in the output path"""
        self.write_file(self.__same_node_ips, content)


if __name__ == '__main__' and os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
    modules = {}
    IPM = "localhost"
    IPA = "0.0.0.0"
    DEF_PORT = 8888
    PORTM = 5001
    RUTA = "./maps/qkd-topology.json"
    modules['qkd'] = TopologyQKD((IPM, PORTM))

    print("Creating ALTO CORE")
    print("Modules:\t", str(modules), "\nAPI IP:\t", str(IPA),
          "\nAPI_PORT:\t", str(DEF_PORT), "\nMailbox:\t", str(PORTM))

    alto = TopologyCreator(modules, IPA, DEF_PORT, PORTM, [["192.168.159.83", 8080]])

    # Hilos para los módulos
    threads = []
    for modulo in modules:
        print("Creating the topology module:", modulo)
        x = threading.Thread(target=alto.gestiona_info, args=(modulo,))
        threads.append(x)
        x.start()

    # Hilo para mailbox
    print("Launching the response manager")
    t_mailbox = threading.Thread(target=alto.mailbox)
    t_mailbox.start()

    # Hilo para lógica de la API REST (si es más que solo Dash)
    print("Launching API REST logic")
    t_api_logic = threading.Thread(target=alto.api.run)
    t_api_logic.start()

    # GUI Dash: en el hilo principal
    print("Starting Dash GUI on main thread")
    if alto.gui_app:
        alto.gui_app.run(debug=True, host="0.0.0.0", port=8050, use_reloader=False)
    else:
        print("Error: No se pudo iniciar la GUI de Dash.")