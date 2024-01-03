#!/usr/bin/env python3

import ipaddress
import os
import json
import networkx
import socket
import threading

from time import sleep
from datetime import datetime
#sys.path.append('/home/ubuntu/docker-alto/network_exposure/')
#from bgp.manage_bgp_speaker import ManageBGPSpeaker
#sys.path.append('alto-ale/')
#from kafka_ale.kafka_api import AltoProducer
#from api_pybatfish import BatfishManager
from yang_alto import RespuestasAlto
#from ipaddress import ip_address, IPv4Address
#from modulos.topology_bgp import TopologyBGP
from modulos.topology_ietf import TopologyIetf
from api.web.alto_http import AltoHttp

DEFAULT_ASN = 0
RR_BGP_0 = "50.50.50.1"
#RR_BGP = BGP_INFO['bgp']['ip']


class TopologyCreator:

    def __init__(self, modules, mode, ip="127.0.0.1", puerto=5000):
        self.d_modules = modules
        #self.exabgp_process = exabgp_process
        #self.props = {}
        self.pids = {}
        self.topology = networkx.Graph()
        self.cost_map = {}
        #self.router_ids = []
        # set path where to write result json files
        self.topology_writer = TopologyFileWriter('/root/')
        #if mode:
        #    self.kafka_p = AltoProducer("localhost", "9092")
        self.vtag = 0
        self.respuesta = RespuestasAlto()
        self.http = AltoHttp(self)
        #self.http.app.run(host=ip, port=puerto)
        #self.h_thread = threading.Thread(target=self.http.run)
        #self.kafka_p = AltoProducer("localhost", "9093")
        #self.ts = {}
        self.endpoints = {}
        #self.bfm = BatfishManager()


    ### Static Methods

    # @staticmethod
    # def discard_message_from_protocol_id(message, discard_protocols):
    #     """Discard message if protocol is inside discard_protocols list"""
    #     return message["protocol-id"] in discard_protocols

    @staticmethod
    def get_hex_id(ip):
        """Get hexadecimal value for certain IP
        :param: ip string"""
        return ''.join(['%02x' % int(w) for w in ip.split('.')])

    @staticmethod
    def check_is_hex(hex_value):
        try:
            int(hex_value, 16)
            return True
        except ValueError:
            return False

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
    def check_if_router_id_is_hex(router_id):
        return router_id.isnumeric()

    @staticmethod
    def hex_to_ip(hex_ip):
        hex_ip = hex_ip.strip("0")
        addr_long = int(hex_ip, 16) & 0xFFFFFFFF
        struct.pack("<L", addr_long)
        return socket.inet_ntoa(struct.pack("<L", addr_long))

    @staticmethod
    def reverse_ip(reversed_ip):
        l = reversed_ip.split(".")
        return '.'.join(l[::-1])

    ### Auxiliar methods

    def ip_type(self, prefix):
        ip=prefix.split("/")[0]
        return "IPv4" if type(ip_address(ip)) is IPv4Address else "IPv6"

    def obtain_pid(self, router):
        """Returns the hashed PID of the router passed as argument. 
            If the PID was already mapped, it uses a dictionary to access to it.
        """
        #tsn = int(datetime.timestamp(datetime.now())*1000000)
        rid = self.get_hex_id(router) if not self.check_is_hex(router) else router
        if rid not in self.ts.keys():
            self.ts[rid] = tsn
        else:
            tsn = self.ts[rid]
        hash_r = hashlib.sha3_384((router + str(tsn)).encode())
        return ('pid%d:%s:%d' % (DEFAULT_ASN, hash_r.hexdigest()[:32], tsn))

    # def create_pid_name(self, lsa, descriptors, area_id):
    #     """Creates partition ID.
    #     with AS number + domain_id + area_id + hexadecimal router_id
    #     """
    #     routers_id = []
    #     desc = lsa[descriptors]
    #     for item in desc:
    #         if "router-id" in item:
    #             routers_id.append(item["router-id"])
    #     autonomous_systems = [item.get("autonomous-system") for item in desc]
    #     domain_ids = [item.get("domain-id", 0) for item in desc]
    #     for router_id, autonomous_system, domain_id in zip(routers_id, autonomous_systems, domain_ids):
    #         pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.get_hex_id(router_id) if not self.check_is_hex(router_id) else router_id)
    #         #pid_name = self.obtain_pid(router_id)
    #         origin = (autonomous_system, domain_id, area_id, router_id)
    #         if pid_name not in self.props:
    #             self.props[pid_name] = []
    #         self.props[pid_name].append(origin)

    # def get_router_id_from_node_descript_list(self, node_descriptors, key: str):
    #     result = []
    #     for descriptor in node_descriptors:
    #         for key_d, value in descriptor.items():
    #             if key_d == key:
    #                 #print(value, key_d)
    #                 if self.check_if_router_id_is_hex(value):
    #                     result.append(self.split_router_ids(value))
    #                 elif "." in value:
    #                     result.append(value)
    #                 else:
    #                     result.append(self.reverse_ip(self.hex_to_ip(value)))
    #     return result

#Public
    def parseo_yang(self, mensaje, tipo):
        return str(tipo) + 'json{"alto-tid":"1.0","time":' + str(datetime.timestamp(datetime.now())) + ',"host":"altoserver-alberto","' + str(tipo) + '":' + str(mensaje) + '},}'

    def compute_netmap(self, asn, redes):
        for router in redes.keys():
            ipv4 = []
            ipv6 = []
            for ip in redes[router]:
                if not ip.endswith("/3", -3, -1):
                    #print(ip[-3:-1])
                    ipv4.append(ip)
                #try:
                #    if type(ipaddress.ip_network(ip)) is IPv4Network:
                #else:
                #        ipv6.append(ip)
                #except:
                #    print("Invalid IP" + str(ip))
            pid = 'pid%d:%s' % (asn, self.get_hex_id(router))
            #pid = self.cyphered_pid(router, asn)
            if len(ipv4):
                if pid not in self.net_map.keys():
                    self.net_map[pid] = {}
                    #self.net_map[pid]['ipv4'] = []
                #self.net_map[pid]["ipv4"] = ipv4
                self.net_map[pid]['ipv4'] = ipv4
            if len(ipv6):
                self.net_map[pid]["ipv6"] = ipv6


    ### Topology generation and information recopilation functions

    # def load_topology(self, lsa, igp_metric):
    #     if lsa.get('ls-nlri-type') == 'bgpls-link':
    #         # Link information
    #         src = self._get_router_id_from_node_descript_list(lsa['local-node-descriptors'], 'router-id')
    #         dst = self._get_router_id_from_node_descript_list(lsa['remote-node-descriptors'], 'router-id')
    #         for i, j in zip(src, dst):
    #             self.topology.add_edge(i, j, weight=igp_metric)
    #     if lsa.get('ls-nlri-type') == 'bgpls-prefix-v4':
    #         # ToDo verify if prefix info is needed and not already provided by node-descriptors
    #         # Node information. Groups origin with its prefixes
    #         origin = self._get_router_id_from_node_descript_list(lsa['node-descriptors'], "router-id")
    #         prefix = self.split_router_ids(lsa['ip-reach-prefix'])
    #         for item in origin:
    #             if item not in self.topology.nodes():
    #                 self.topology.add_node(item)
    #             if 'prefixes' not in self.topology.nodes[item]:
    #                 self.topology.nodes[item]['prefixes'] = []
    #             self.topology.nodes[item]['prefixes'].append(prefix)
    #     if lsa.get('ls-nlri-type') == "bgpls-node":
    #         # If ls-nlri-type is not present or is not of type bgpls-link or bgpls-prefix-v4
    #         # add node to topology if not present
    #         node_descriptors = self._get_router_id_from_node_descript_list(lsa['node-descriptors'], 'router-id')
    #         self.router_ids.append(node_descriptors)
    #         for node_descriptor in node_descriptors:
    #             if node_descriptor not in self.topology.nodes():
    #                 self.topology.add_node(node_descriptor)

    # def load_pid_prop(self, lsa, ls_area_id):
    #     if 'node-descriptors' in lsa:
    #         self.create_pid_name(lsa, descriptors='node-descriptors', area_id=ls_area_id)
    #     if 'local-node-descriptors' in lsa:
    #         self.create_pid_name(lsa, descriptors='local-node-descriptors', area_id=ls_area_id)
    #     if 'remote-node-descriptors' in lsa:
    #         self.create_pid_name(lsa, descriptors='remote-node-descriptors', area_id=ls_area_id)

    # def load_pids(self, ipv4db):
    #     # self.pids stores the result of networkmap
    #     for rr_bgp in [RR_BGP_0]:
    #         for prefix, data in ipv4db[rr_bgp]['ipv4'].items():
    #             pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.get_hex_id(data['next-hop']))
    #             #pid_name = self.obtain_pid(data['next-hop'])
    #             tipo=self.ip_type(prefix)
    #             if pid_name not in self.pids:
    #                 self.pids[pid_name] = {}
    #             if tipo not in self.pids[pid_name]:
    #                 self.pids[pid_name][tipo]=[]
    #             if prefix not in self.pids[pid_name][tipo]:
    #                 self.pids[pid_name][tipo].append(prefix)


    def compute_costmap(self):
        # shortest_paths is a dict by source and target that contains the shortest path length for
        # that source and destination
        shortest_paths = dict(networkx.shortest_paths.all_pairs_dijkstra_path_length(self.topology))
        for src, dest_pids in shortest_paths.items():
            src_pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.get_hex_id(src))
            #src_pid_name = self.obtain_pid(src)
            for dest_pid, weight in dest_pids.items():
                dst_pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.get_hex_id(dest_pid))
                #dst_pid_name = self.obtain_pid(dest_pid)
                if src_pid_name not in self.cost_map:
                    self.cost_map[src_pid_name] = {}
                self.cost_map[src_pid_name][dst_pid_name] = weight
    
    def compute_pid_endpoint(self, endpoint):
        #Vamos a recibir la IP del
        ip_e = ipaddress.IPv4Address(endpoint)
        red = "0.0.0.0/-1"
        pid_e = 0
        #print(str( self.net_map))
        for pid in self.net_map:
            #print("pid", pid)
            for prefijo in self.net_map[pid]["ipv4"]:
                if ip_e in ipaddress.IPv4Network(prefijo):
                    if int(prefijo.split("/")[1]) > int(red.split("/")[1]):
                        red = prefijo
                        pid_e = pid
        #print(endpoint,self.net_map[pid_e]["ipv4"])
        return pid_e


    def launch_api(self):
        t_http = threading.Thread(target=self.http.run)
        t_http.start()


    ### RFC7285 functions
    def get_costs_map_by_pid(self, pid):
        #pid = "pid0:" + str(npid)
        #print(pid)
        #print(str(self.pids))
        if pid in self.cost_map.keys():
            #print(str(self.pids))
            #print(str(self.cost_map))
            return self.respuesta.crear_respuesta("filtro", "networkmap-default", self.vtag, str(self.cost_map[pid]))
        else:
            return "404: Not Found"

    def get_properties(self, pid, properties):
        #return str(self.bf.session.q.nodeProperties().answer().frame())
        #pid = self.__compute_pid_endpoint(endpoint)
        if pid:
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
                            return f'{properties} not valid for {pid}'
            #print(resp)
            return self.__resp.respuesta_prop("properties", self.__vtag, str(resp))

        
        
        
        #return str(self.bf.session.q.nodeProperties().answer().frame())
        return "Implementation in proccess. Sorry dude"

    def get_endpoint_costs(self, endpoint):
        pid = self.endpoints.get(endpoint)
        if pid:
                return self.get_costs_map_by_pid(pid["pid"])
        else:
                return "Endpoint not valid"
        #return "Implementation in proccess. Sorry dude"


    def get_maps(self):
        return ('{"network_map":' + self.get_net_map() + ', "costs_map":' + self.get_costs_map() + '}')

    def get_costs_map(self):
        return self.respuesta.crear_respuesta("cost-map","networkmap-default", 0, str(self.cost_map))
        #return self.resp.crear_respuesta("cost-map", "networkmap-default", self.vtag, str(self.cost_map))

    def get_net_map(self):
        return self.respuesta.crear_respuesta("pid-map", "networkmap-default", self.vtag, str(self.pids))

    def get_directory(self):
        return self.respuesta.indice()


    ### Ampliation functions
    
    def shortest_path(self, a, b):
        try:
            return networkx.dijkstra_path(self.topology, a, b)
        except networkx.exception.NetworkXNoPath as e:
            return []
        except Exception as e:
            print(e)
            return (-1)

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
    
    ### Manager function
    def gestiona_info(self, fuente):
        if fuente in self.d_modules.keys():
            self.d_modules[fuente].manage_topology_updates()

    def mailbox(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('localhost',8081))
        print("Waiting...")
        #self.h_thread.start()        
        while 1:
            topo = s.recv(16384)
            topo = topo.decode()
            #print(topo)
            # Aquí se deben de gestionar los datos recibidos
            # Recibe una lista de nodos, una lista de ejes (con pesos), un indicador de la métrica pasada y la funete.
            # Los nodos ya deben estar parseados según el AS.
            #if asn != '':
                #self.compute_costmap(int(asn), topology)
                #self.compute_netmap(int(asn), pids)
                #self.vtag = str(int(datetime.timestamp(datetime.now())*1000000))
                #self.evaluate_endpoints()
                #self.topology = topology
                #self.topology_writer.write_same_ips(self.router_ids)
                #self.topology_writer.write_pid_file(self.filter_net_map(1))
                #self.topology_writer.write_cost_map(self.filter_cost_map(1))
                #print("Nodes loaded:\t" ,str(self.cost_map.keys()))
            try:
                datos = json.loads(str(topo).replace('\t', '').replace('\n', '').strip())
                ejes = datos["data"]["costs-list"]
                nodos = datos["data"]["nodes-list"]
                for nodo in nodos:
                    self.topology.add_node(nodo)
                for eje in ejes:
                    #print(eje)
                    leje = eval(eje.replace("(","[").replace(")","]"))
                    self.topology.add_edge(leje[0], leje[1], weight=leje[2])
                self.compute_costmap()
                #print(datos["data"]["pids"])
                #self.compute_netmap()
                self.pids = datos["data"]["pids"]
                #print("Todo correcto Hulio")
                #self.comput-e_netmap(int(asn), pids)
            except:
                print("Error al procesar:\n", str(topo))
            #print("netmap:\t" + str(datos["data"]["pids"]).replace("'",'"'))
            #print("costmap:\t" + str(self.cost_map).replace("'",'"'))
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
                self.endpoints[user["ipv4"][0]]=user




class TopologyFileWriter:

    def __init__(self, output_path):
        self.output_path = output_path
        self.pid_file = 'pid_file.json'
        self.cost_map_file = 'cost_map.json'
        self.same_node_ips = "router_ids.json"

    def write_file(self, file_name, content_to_write):
        """Writes file_name in output_file"""
        full_path = os.path.join(self.output_path, file_name)
        with open(full_path, 'w') as out_file:
            json.dump(content_to_write, out_file, indent=4)

    def write_pid_file(self, content):
        self.write_file(self.pid_file, content)

    def write_cost_map(self, content):
        self.write_file(self.cost_map_file, content)

    def write_same_ips(self, content):
        self.write_file(self.same_node_ips, content)


### Aux clases ###
class TopologyUpdateThread(threading.Thread):

    def __init__(self, topo_manager):
        threading.Thread.__init__(self)
        self.tp_mng = topo_manager

    def run (self):
        t,a,p,c = self.tp_mng.manage_bgp_speaker_updates()
        return t,a,p,c

### Aux clases ###
class TopologyExpoThread(threading.Thread):

    def __init__(self, a):
        threading.Thread.__init__(self)
        self.api = AltoHttp(a)

    def run (self):
        self.api.run()





if __name__ == '__main__':
    '''speaker_bgp = ManageBGPSpeaker()
    exabgp_process = speaker_bgp.check_tcp_connection()
    
    topology_creator = TopologyCreator(exabgp_process,0)
    topology_creator.manage_ietf_speaker_updates()
    '''
    modules={}
    #modules['bgp'] = TopologyBGP(('localhost',8081))
    modules['ietf'] = TopologyIetf(('localhost',8081))
    print("Creando ALTO CORE")
    alto = TopologyCreator(modules, 0, "127.0.0.1", 5000)

    threads = list()
    for modulo in modules.keys():
        print("Creando el módulo de topología:",modulo)
        x = threading.Thread(target=alto.gestiona_info, args=(modulo,))#, daemon=True)
        threads.append(x)
        x.start()

    
    
    print("Lanzando API REST")
    t_api = threading.Thread(target=alto.http.run)
    t_api.start()
    #alto.launch_api()
    print("Lanzando gestor de respuestas")
    alto.mailbox()


    #Inclusión de prueba
