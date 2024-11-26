#!/usr/bin/env python3
# © 2024 Telefónica Innovación Digital, All rights reserved

import ipaddress
import math
import os
import json
import re
import struct
import networkx
import socket
import threading
import ipaddress
import yaml
import logging


from time import sleep
from datetime import datetime, timedelta
from yang_alto import RespuestasAlto
#from ipaddress import ip_address, IPv4Address
from modulos.topology_ndt import TopologyNDT
from modulos.topology_ietf import TopologyIetf
from modulos.topology_bgp import TopologyBGP
#from api.desire.alto_http import AltoHttp
from api.web.alto_http import AltoHttp

DEFAULT_ASN = 0
DEF_PORT = 8888
DEF_IP = "0.0.0.0"
ERRORES = { "sintax" : "E_SYNTAX", "campo" : "E_MISSING_FIELD", "tipo" : "E_INVALID_FIELD_TYPE", "valor" : "E_INVALID_FIELD_VALUE" }
TPS = {"xrv11":{"xrv13":"Gi0/0/0/0","xrv15":"Gi0/0/0/2"},"xrv12":{"xrv14":"Gi0/0/0/0","xrv15":"Gi0/0/0/1"},"xrv13":{"xrv11":"Gi0/0/0/0","xrv14":"Gi0/0/0/1","xrv16":"Gi0/0/0/2"},"xrv14":{"xrv12":"Gi0/0/0/0","xrv13":"Gi0/0/0/1","xrv18":"Gi0/0/0/2"},"xrv15":{"xrv11":"Gi0/0/0/2","xrv12":"Gi0/0/0/1"},"xrv16":{"xrv13":"Gi0/0/0/2","xrv17":"Gi0/0/0/0"},"xrv17":{"xrv16":"Gi0/0/0/0","xrv18":"Gi0/0/0/1"},"xrv18":{"xrv14":"Gi0/0/0/2","xrv17":"Gi0/0/0/1"}}
time_interval_size = 120 #seconds
number_of_intervals = 3

class TopologyCreator:

    def __init__(self, modules, ip="127.0.0.1", puerto=8000, portm=5000, output="./topology_metrics.json"):
        self.__d_modules = modules
        self.__redes = []
        self.__topology = networkx.Graph()
        self.__cost_map = {}
        self.__net_map = {}
        self.port_module = portm
        # set path where to write result json files
        self.__api = AltoHttp(self, ip, puerto)        
        self.__vtag = 0
        self.__respuesta = RespuestasAlto()

        self.__endpoints = {}
        
        # Cost Calendar parameters
        self.list_topologies = []        
        self.cost_calendar = {}
        self.init_time = datetime.now()
        #self.create_costcalendar()
        
        # Writer
        self.saver = TopologyFileWriter(output)

        # Loggs
        logging.basicConfig(format="%(levelname)s:%(message)s", level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        timestamp = int(datetime.now().timestamp())
        self.filename = "./logs/alto.log"
        with open(self.filename, "w", encoding='utf-8') as f:
            f.write(f"Starting ALTO: {timestamp}")



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
            #pid = 'pid%d:%s' % (asn, self.get_hex_id(router))
            pid = router
            #pid = self.cyphered_pid(router, asn)
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
            src_pid_name = src
            # src_pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.get_hex_id(src))
            # src_pid_name = self.obtain_pid(src)
            for dest_pid, weight in dest_pids.items():
                #dst_pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.get_hex_id(dest_pid))
                dst_pid_name = dest_pid
                #dst_pid_name = self.obtain_pid(dest_pid)
                if src_pid_name not in cost_map:
                    cost_map[src_pid_name] = {}
                cost_map[src_pid_name][dst_pid_name] = weight
        return cost_map
    
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


    def compute_costcalendar(self):
        # shortest_paths is a dict by source and target that contains the shortest path length for
        # that source and destination. This procedure we have as many times as there are topologies in list_topologies
        # As result we obtain a topology with an array of weights of each topology
        self.cost_calendar = {}
        i=0
        for i in range(number_of_intervals):
            shortest_paths = dict(networkx.shortest_paths.all_pairs_dijkstra_path_length(self.list_topologies[i]))
            for src, dest_pids in shortest_paths.items():
                src_pid_name = src
                # src_pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.get_hex_id(src))
                # src_pid_name = self.obtain_pid(src)
                for dest_pid, weight in dest_pids.items():
                    dst_pid_name = dest_pid
                    # dst_pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.get_hex_id(dest_pid))
                    # dst_pid_name = self.obtain_pid(dest_pid)
                    if src_pid_name not in self.cost_calendar:
                        self.cost_calendar[src_pid_name] = {}
                    if dst_pid_name not in self.cost_calendar[src_pid_name]:
                        self.cost_calendar[src_pid_name][dst_pid_name]=[-1 for _ in range(number_of_intervals)] 
                    self.cost_calendar[src_pid_name][dst_pid_name][i]=weight
        self.logger.info("COST CALENDAR:\t %s", str(self.cost_calendar))
        self.logger.info("Timestamp:\t %s", str(datetime.now()))

    # curl -X POST -H "Content-Type: application/json" -d @new_topology.json localhost:9999/update-expected-topology
    def update_topology(self, new_time, new_topology):
        # manage update timing: if it's in the past, show the current topology, and if it's in the future
        # update the topology and its metrics to update the cost calendar
        if isinstance(new_time, str):
            update_time = datetime.strptime(new_time, '%Y-%m-%d %H:%M:%S.%f')
            
        time = self.init_time + timedelta(seconds=time_interval_size)
        end_update = self.init_time + timedelta(seconds=(number_of_intervals*time_interval_size))
        self.logger.info(f'la hora de actualizacion es  {update_time} y time es  {time}')
        self.logger.info("Timestamp:\t %s", str(datetime.now()))
        if update_time < self.init_time and update_time > end_update: # confirm far past--> else
            self.logger.debug('Estoy en if')
            self.compute_costcalendar()
        elif update_time < time: # far past
            self.logger.debug('Estoy en elif')
            self.compute_costcalendar()
        else: # update costcalendar
           i=0
           self.logger.debug('Estoy en else')
           time_dif = update_time - self.init_time
           update_column =  math.floor(time_dif.total_seconds()/time_interval_size)
           self.logger.debug(update_column)
           self.logger.debug(self.__topology.nodes(), 'antes de actualizar')
           updated_topology = self.__d_modules["ietf"].manage_update_topology(new_topology)
           self.logger.debug(updated_topology.nodes(), 'despues de actualizar')

           for i in range(number_of_intervals):
               if i >= update_column:
                   self.list_topologies[i]=0
                   self.list_topologies[i]=networkx.Graph(updated_topology)
           self.compute_costcalendar()

    def create_costcalendar(self):
        # Create a list with number_of_intervals columns where store copies of the topology
        # if isinstance(cost_calendar_start_time, datetime):
        #    update_time = datetime(cost_calendar_start_time)
        self.list_topologies = [networkx.Graph(self.__topology) for _ in range(number_of_intervals)]
        # self.update_topology(update_time, new_topology)
        #return self.__respuesta.get_respuesta_costcalendar("get-cost-calendar", self.vtag)
        self.compute_costcalendar()


    def get_costcalendar(self):
        return self.__respuesta.crear_respuesta("cost-calendar", '', "costcalendar-default", self.__vtag, [time_interval_size, number_of_intervals,self.cost_calendar]) 

    ### Manager function
    def gestiona_info(self, fuente):
        if fuente in self.__d_modules.keys():
            if fuente == "ndt":
                self.__d_modules[fuente].run()            
            else:    
                self.__d_modules[fuente].manage_topology_updates()

    def get_tps(self, nodo):
        tps = []
        for dest, tp in TPS[nodo].items():
            tps.append({"tp-id":tp})
        return tps

    def graph_to_topology_json(self, topology, time):
        # Obtener la hora actual para el campo "calendar_start_time"
        calendar_start_time = time.isoformat()
        
        # Lista de nodos y enlaces
        nodes = []
        links = []
        
        # Procesar nodos
        for node_id, data in topology.nodes(data=True):
            node = {
                "node-id": node_id,
                "ietf-l3-unicast-topology:l3-node-attributes": {
                    "name": data.get("name", ""),
                    "router-id": node_id,
                    "termination-point":self.get_tps(node_id),
                    "prefix": [{"prefix": prefix} for prefix in data.get("prefixes", [])]
                },
                "ietf-ne-commissioning:commissioning-configs": {
                    "system-config": {
                        "openconfig-system:system": {
                            "ssh-server": {
                                "state": {
                                    "enable": data.get("ssh_enabled", "True"),
                                    "protocol-version": "V2"
                                }
                            },
                            "telnet-server": {
                                "state": {
                                    "enable": data.get("telnet_enabled", "False")
                                }
                            }
                        }
                    }
                },
                "ietf-network-topology:termination-point": [
                    {
                        "tp-id": tp_id,
                        "ietf-l3-unicast-topology:l3-termination-point-attributes": {
                            "ip-address": [tp.get("ip_address")] if tp.get("ip_address") else [],
                            "ietf-l3-isis-topology:isis-termination-point-attributes": {
                                "level": tp.get("level", "level-2")
                            }
                        }
                    } for tp_id, tp in data.get("termination_points", {}).items()
                ]
            }
            nodes.append(node)
        
        # Procesar enlaces
        for u, v, data in topology.edges(data=True):
            link = {
                "link-id": f"{data.get('link_name', f'{u}-{TPS[u][v]}-{v}-{TPS[v][u]}')}",
                "source":{
                    "source-node":u,
                    "source-tp":TPS[u][v]
                },
                "destination":{
                    "dest-node":v,
                    "dest-tp":TPS[v][u]
                },
                "ietf-l3-unicast-topology:l3-link-attributes": {
                    "routingcost": data.get("weight", -1),
                    "latency": data.get("latency", -1),
                    "bandwidth": data.get("bandwidth", -1),
                    "tefsdn-topology:domain-id": data.get("domain_id", "0"),
                    "tefsdn-topology:link-attributes": {
                        "level": data.get("level", "2")
                    }
                }
            }
            links.append(link)
        
        # Estructura final
        topology_json = {
            "calendar_start_time": calendar_start_time,
            "ietf-network:networks": {
                "network": [
                    {
                        "network-id": "0 : 0 : 0 ISIS",
                        "network-types": {
                            "ietf-l3-isis-topology:isis-topology": {},
                            "ietf-l3-unicast-topology:l3-unicast-topology": {}
                        },
                        "node": nodes,
                        "ietf-network-topology:link": links
                    }
                ]
            }
        }
        #print(topology_json)        
        return topology_json

    def calendar_2_ietf(self):
        topos = []
        tiempo  = self.init_time
        for topo in self.list_topologies:
            topos.append(self.graph_to_topology_json(topo, tiempo))
            tiempo = tiempo + timedelta(seconds=time_interval_size)
        return topos


    def mailbox(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('localhost',self.port_module))
        self.logger.debug("Waiting...")      
        while 1:
            topo = s.recv(16384)
            self.logger.debug("Received:" + str(len(topo)) + " Bytes")
            topo = topo.decode()
            # try:
            if 1:
                datos = json.loads(topo)
                self.logger.info(f"DATOS RECIBIDOS:\t{datos}")
                self.logger.info("Timestamp:\t %s", str(datetime.now()))
                if datos["meta"]["source"] == 5:
                    new_topology = datos["data"]["topology"]
                    update_time = datos["data"]["start-time"]
                    self.update_topology(update_time, new_topology)
                else:
                    # print("Entramos en el BGP")
                    ejes = datos["data"]["costs-list"]
                    nodos = datos["data"]["nodes-list"]
                    self.__redes = datos["data"]["prefixes"]
                    nodos_nombre = datos["data"]["pids"]
                    #print(str(self.__redes))
                    for nodo in nodos:
                        self.__topology.add_node(nodos_nombre[nodo])
                    for eje in ejes:
                        #print(eje)
                        #leje = eval(eje.replace("(","[").replace(")","]"))
                        # self.__topology.add_edge(nodos_nombre[eje[0]], nodos_nombre[eje[1]], weight=eje[2])
                        self.__topology.add_edge(nodos_nombre[eje[0]], nodos_nombre[eje[1]], **eje[2])
                    self.__vtag = str(int(datetime.now().timestamp()*1e6))
                    self.logger.info("Actualizada la topología va BGP en:\t %s", str(datetime.now()))
                    
                    self.__net_map = self.compute_netmap(DEFAULT_ASN, self.__redes)
                    self.__cost_map = self.compute_costmap(self.__topology)
                    
                    if not self.list_topologies:
                        self.list_topologies = [networkx.Graph(self.__topology) for _ in range(number_of_intervals)]
                    else:
                        self.list_topologies[0] = self.__topology
                        
                    self.compute_costcalendar()

                    topos = self.calendar_2_ietf()
                    self.saver.write_file("", topos)                    
                    #print(topos)

            else:
            #except:
                self.logger.error("Error al procesar:\n %s", str(topo))
                self.logger.error("Timestamp:\t %s", str(datetime.now()))
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

    def get_topology(self):
        with open('./topology.json', 'r') as source:
            jason = source.read()
            jason = jason.replace('\t', '').replace('\n', '').replace("'", '"').strip()
            return json.loads(str(jason))
        return '{}'

class TopologyFileWriter:

    def __init__(self, output_path="./"):
        self.__output_path = output_path
        self.__pid_file = 'pid_file.json'
        self.__cost_map_file = 'cost_map.json'
        self.__same_node_ips = "router_ids.json"

    def write_file(self, file_name, content_to_write):
        """Writes file_name in output_file"""
        if len(file_name) > 0:
            full_path = os.path.join(self.__output_path, file_name)
        else:
            full_path = self.__output_path
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

    
    modules = {}
    #portm = 5000


    # modules['bgp'] = TopologyBGP(('localhost',5000))
    modules['ietf'] = TopologyIetf(('localhost',5000))
    modules['ndt'] = TopologyNDT(('localhost',5000))



    print("Creando ALTO CORE")
    alto = TopologyCreator(modules, DEF_IP, DEF_PORT, portm=5000, output="/home/ubuntu/change_scheduler/topologies/cost_calendar2.json")
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

