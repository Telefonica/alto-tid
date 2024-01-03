#!/usr/bin/env python3

import os
import sys
import json
import re
import networkx
import socket
import struct
import hashlib
import threading
import flask

from time import sleep
from datetime import datetime
sys.path.append('cdn-alto/')
sys.path.append('alto-ale/')
from kafka_ale.kafka_api import AltoProducer
#from api_pybatfish import BatfishManager
from yang_alto import RespuestasAlto
from ipaddress import ip_address, IPv4Address
from modulos.topology_bgp import TopologyBGP
from modulos.topology_ietf import TopologyIetf

DEFAULT_ASN = 0
RR_BGP_0 = "50.50.50.1"
#RR_BGP = BGP_INFO['bgp']['ip']



#Parte API
app = flask.Flask(__name__)
app.config["DEBUG"] = True

@app.route('/', methods=['GET'])
def home():
    return '''
    <h1>API DE ACCESO AL SERVICE ALTO DE PRUEBAS</h1>
    <h2>Servicios disponibles:</h2>
    <p><ul>
    <li>Todos los camimos disjuntos entre A y B: <b><tt> /all/&ltstring:a&gt/&ltstring:b&gt </b></tt></li>
    <li>Camino más corto entre A y B: <b><tt> /best/&ltstring:a&gt/&ltstring:b&gt </b></tt></li>
    <li>Mapa de costes: /costs </li>
    <li>Mapa de PIDs: /pids </li>
    </ul></p>
    '''

###################################
##                               ##
#   Services defined in RFC 7285  #
##                               ##
###################################

# Map-Filteriong Service
@app.route('/costmap/filter/<string:pid>', methods=['GET'])
def api_costs_by_pid(pid):
    return flask.jsonify(alto.get_costs_map_by_pid(pid))

#Endpoint Property Service
@app.route('/properties/<string:pid>', methods=['GET'])
def api_properties(pid):
    return flask.jsonify(alto.get_properties(pid))

#Map Service
@app.route('/maps', methods=['GET'])
def api_maps():
    return flask.jsonify(alto.get_maps())

#Network Map service
@app.route('/costmap', methods=['GET'])
def api_costs():
    return flask.jsonify(alto.get_costs_map())

@app.route('/networkmap', methods=['GET'])
def api_pids():
    return flask.jsonify(alto.get_pids())

@app.route('/directory', methods=['GET'])
def api_directory():
    return flask.jsonify(alto.get_directory())


###################################
##                               ##
#           Ampliations           #
##                               ##
###################################


#All possible paths between A and B without any common node
@app.route('/all/<string:a>/<string:b>', methods=['GET'])
def api_all(a, b):
    return flask.jsonify(alto.parseo_yang(str(alto.all_maps(alto.topology,a,b)),"all-paths"))

#Best path between A and B
@app.route('/best/<string:a>/<string:b>', methods=['GET'])
def api_shortest(a, b):
    return flask.jsonify(str(shortest_path(a, b)))


class TopologyCreator:

    def __init__(self, modules, mode):
        self.d_modules = modules 
        self.__props = {}
        self.__pids = {}
        self.__topology = networkx.Graph()
        self.__cost_map = {}
        self.__router_ids = []
        # set path where to write result json files
        self.__topology_writer = TopologyFileWriter('/root/')
        if mode:
            self.kafka_p = AltoProducer("localhost", "9092")
        #self.kafka_p = AltoProducer("localhost", "9093")
        self.__ts = {}
        #self.bfm = BatfishManager()
        self.__vtag = 0
        self.__resp = RespuestasAlto()
        #self.hilos = self.lanzadera()
    ### Static Methods

    @staticmethod
    def __discard_message_from_protocol_id(message, discard_protocols):
        """Discard message if protocol is inside discard_protocols list"""
        return message["protocol-id"] in discard_protocols

    @staticmethod
    def __get_hex_id(ip):
        """Get hexadecimal value for certain IP
        :param: ip string"""
        return ''.join(['%02x' % int(w) for w in ip.split('.')])

    @staticmethod
    def __check_is_hex(hex_value):
        try:
            int(hex_value, 16)
            return True
        except ValueError:
            return False

    @staticmethod
    def __split_router_ids(router_id: str):
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
    def __check_if_router_id_is_hex(router_id):
        return router_id.isnumeric()

    @staticmethod
    def __hex_to_ip(hex_ip):
        hex_ip = hex_ip.strip("0")
        addr_long = int(hex_ip, 16) & 0xFFFFFFFF
        struct.pack("<L", addr_long)
        return socket.inet_ntoa(struct.pack("<L", addr_long))

    @staticmethod
    def __reverse_ip(reversed_ip):
        l = reversed_ip.split(".")
        return '.'.join(l[::-1])



    ### Auxiliar methods

    def __ip_type(self, prefix):
        ip=prefix.split("/")[0]
        return "IPv4" if type(ip_address(ip)) is IPv4Address else "IPv6"

    def __obtain_pid(self, router):
        """Returns the hashed PID of the router passed as argument. 
            If the PID was already mapped, it uses a dictionary to access to it.
        """
        tsn = int(datetime.timestamp(datetime.now())*1000000)
        rid = self.__get_hex_id(router) if not self.__check_is_hex(router) else router
        if rid not in self.__ts.keys():
            self.__ts[rid] = tsn
        else:
            tsn = self.__ts[rid]
        hash_r = hashlib.sha3_384((router + str(tsn)).encode())
        return ('pid%d:%s:%d' % (DEFAULT_ASN, hash_r.hexdigest()[:32], tsn))

    def __create_pid_name(self, lsa, descriptors, area_id):
        """Creates partition ID.
        with AS number + domain_id + area_id + hexadecimal router_id
        """
        routers_id = []
        desc = lsa[descriptors]
        for item in desc:
            if "router-id" in item:
                routers_id.append(item["router-id"])
        autonomous_systems = [item.get("autonomous-system") for item in desc]
        domain_ids = [item.get("domain-id", 0) for item in desc]
        for router_id, autonomous_system, domain_id in zip(routers_id, autonomous_systems, domain_ids):
            pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.__get_hex_id(router_id) if not self.__check_is_hex(router_id) else router_id)
            #pid_name = self.__obtain_pid(router_id)
            origin = (autonomous_system, domain_id, area_id, router_id)
            if pid_name not in self.__props:
                self.__props[pid_name] = []
            self.__props[pid_name].append(origin)

    def ___get_router_id_from_node_descript_list(self, node_descriptors, key: str):
        result = []
        for descriptor in node_descriptors:
            for key_d, value in descriptor.items():
                if key_d == key:
                    #print(value, key_d)
                    if self.__check_if_router_id_is_hex(value):
                        result.append(self.__split_router_ids(value))
                    elif "." in value:
                        result.append(value)
                    else:
                        result.append(self.__reverse_ip(self.__hex_to_ip(value)))
        return result

    def parseo_yang(self, mensaje, tipo):
        return str(tipo) + 'json{"alto-tid":"1.0","time":' + str(datetime.timestamp(datetime.now())) + ',"host":"altoserver-alberto","' + str(tipo) + '":' + str(mensaje) + '},}'



    ### Topology generation and information recopilation functions

    def __load_topology(self, d_pids, l_ejes):            
        for pid in d_pids.keys():
            if d_pids[pid] not in self.__topology.nodes():
                self.__topology.add_node(d_pids[pid])
            self.__pids[pid] = d_pids[pid]
        for eje in l_ejes:
            src, des, metric = eje.strip("() ").replace("'","").replace('"',"").split(",")
            #print(src + '\t' + des + '\t' + str(metric))
            self.__topology.add_edge(src, des, weight=int(metric))
        print("Topology loaded")
        print(self.__pids)
        print(str(self.__topology.edges()))



    def __load_pid_prop(self, lsa, ls_area_id):
        if 'node-descriptors' in lsa:
            self.__create_pid_name(lsa, descriptors='node-descriptors', area_id=ls_area_id)
        if 'local-node-descriptors' in lsa:
            self.__create_pid_name(lsa, descriptors='local-node-descriptors', area_id=ls_area_id)
        if 'remote-node-descriptors' in lsa:
            self.__create_pid_name(lsa, descriptors='remote-node-descriptors', area_id=ls_area_id)

    def __load_pids(self, ipv4db):
        # self.__pids stores the result of networkmap
        for rr_bgp in [RR_BGP_0]:
            for prefix, data in ipv4db[rr_bgp]['ipv4'].items():
                pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.__get_hex_id(data['next-hop']))
                #pid_name = self.__obtain_pid(data['next-hop'])
                tipo=self.__ip_type(prefix)
                if pid_name not in self.__pids:
                    self.__pids[pid_name] = {}
                if tipo not in self.__pids[pid_name]:
                    self.__pids[pid_name][tipo]=[]
                if prefix not in self.__pids[pid_name][tipo]:
                    self.__pids[pid_name][tipo].append(prefix)

    def __compute_costmap(self):
        # shortest_paths is a dict by source and target that contains the shortest path length for
        # that source and destination
        shortest_paths = dict(networkx.shortest_paths.all_pairs_dijkstra_path_length(self.__topology))
        ctrl = 0
        for src, dest_pids in shortest_paths.items():
            for key in self.__pids.keys():
                if self.__pids[key] == src:
                    src_pid_name = key
                    ctrl = 1
                    break
            if ctrl == 0:
                src_pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.__get_hex_id(src))
            #src_pid_name = self.__obtain_pid(src)
            for dest_pid, weight in dest_pids.items():           
                for key in self.__pids.keys():
                    if self.__pids[key] == dest_pid:
                        dst_pid_name = key
                        ctrl = 1
                        break
                if ctrl == 0:
                    dst_pid_name = 'pid%d:%s' % (DEFAULT_ASN, self.__get_hex_id(dest_pid))
                #dst_pid_name = self.__obtain_pid(dest_pid)
                if src_pid_name not in self.__cost_map:
                    self.__cost_map[src_pid_name] = {}
                self.__cost_map[src_pid_name][dst_pid_name] = weight


    ### RFC7285 functions
    def get_costs_map_by_pid(self, pid):
        #pid = "pid0:" + str(npid)
        #print(pid)
        #print(str(self.__pids))
        if pid in self.__cost_map.keys():
            #print(str(self.__pids))
            #print(str(self.__cost_map))
            return self.__resp.crear_respuesta("filtro", "networkmap-default", self.__vtag, str(self.__cost_map[pid]))
        else:
            return "404: Not Found"

    def get_properties(self, pid):
        #return str(self.bf.session.q.nodeProperties().answer().frame())
        return "Implementation in proccess. Sorry dude"

    def get_endpoint_costs(self, pid):
        return "Implementation in proccess. Sorry dude"

    def get_maps(self):
        return ('{"pids_map":' + self.get_pids() + ', "costs_map":' + self.get_costs_map() + '}')

    def get_costs_map(self):
        print(self.__cost_map)
        return self.__resp.crear_respuesta("cost-map", "networkmap-default", self.__vtag, str(self.__cost_map))

    def get_pids(self):
        return self.__resp.crear_respuesta("pid-map", "networkmap-default", self.__vtag, str(self.__pids))

    def get_directory(self):
        return self.__resp.indice()

    ### Ampliation functions
    
    def shortest_path(self, a, b):
        try:
            return networkx.dijkstra_path(self.__topology, a, b)
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

    def lanzadera(self):
        threads = list()
        for modulo in self.d_modules.keys():
            #print(modulo)
            x = threading.Thread(target=self.gestiona_info, args=(modulo,))#, daemon=True)
            threads.append(x)
            x.start()
        #x = threading.Thread(target=self.mailbox)
        #threads.append(x)
        #x.start()
        return threads


    def procesar(self, s_topo:str):
        #print(s_topo)
        try:
            topo = json.loads(s_topo)
        except Exception as e:
            print(e)
            print('\t' + s_topo)
            return

        if topo['meta']['action'] == 1:
            self.__load_topology(topo['data']['pids'], topo['data']['costs-list'])
        else:
            self.eliminar(topo['data']['ejes'])

        self.__compute_costmap() 
        

    ### Manager function
    def gestiona_info(self, fuente):
        if fuente in self.d_modules.keys():
            self.d_modules[fuente].manage_topology_updates()

    def mailbox(self, port=8080):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('localhost',port))
        print("Waiting...")
        while 1:
            topo = s.recv(4096)
            print("Recibido:")
            topo = topo.decode()
            self.procesar(topo)
            # Aquí se deben de gestionar los datos recibidos
            # Recibe una lista de nodos, una lista de ejes (con pesos), un indicador de la métrica pasada y la funete.
            # Los nodos ya deben estar parseados según el AS.



class TopologyFileWriter:

    def __init__(self, output_path):
        self.output_path = output_path
        self.pid_file = 'pid_file.json'
        self.__cost_map_file = 'cost_map.json'
        self.same_node_ips = "router_ids.json"

    def write_file(self, file_name, content_to_write):
        """Writes file_name in output_file"""
        full_path = os.path.join(self.output_path, file_name)
        with open(full_path, 'w') as out_file:
            json.dump(content_to_write, out_file, indent=4)

    def write_pid_file(self, content):
        self.write_file(self.pid_file, content)

    def write_cost_map(self, content):
        self.write_file(self.__cost_map_file, content)

    def write_same_ips(self, content):
        self.write_file(self.same_node_ips, content)



if __name__ == '__main__':
    #Creation of ALTO modules
    modules={}
    modules['bgp'] = TopologyBGP(('localhost',8080))
    #modules['ietf'] = TopologyIetf(('localhost',8081))

    alto = TopologyCreator(modules, 0)
    threads = list()

    for modulo in modules.keys():
        print(modulo)
        x = threading.Thread(target=alto.gestiona_info, args=(modulo,))#, daemon=True)
        threads.append(x)
        x.start()

    a = threading.Thread(target=alto.mailbox)
    threads.append(a)
    a.start()

    app.run()
