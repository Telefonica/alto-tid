#!/usr/bin/env python3

# Import section
import threading
import json
import networkx
import ipaddress
import hashlib
from datetime import datetime

# Internals imports
from topology_maps_generator import TopologyCreator
from topology_writer import TopologyFileWriter
from parsers.yang_alto import RespuestasAlto
#from api.web.alto_http import AltoHttp
from kafka_ale.kafka_api import AltoProducer
# Global information section

RUTA = "/root/cdn-alto/alto-tid"

# ALTO class
class AltoCore:
    
    def __init__(self, topo_manager, api):
        self.__topology_creator = topo_manager
        self.__topology_writer = TopologyFileWriter(RUTA + '/maps')
        self.__resp = RespuestasAlto()
        self.__topology = networkx.DiGraph()
        self.__net_map = {}
        self.__cost_map = {}
        #self.__http = AltoHttp(self)
        #self.h_thread = threading.Thread(target=self.__http.run)
        self.__endpoints = {}
        self.__ts = {} #timestamp dictionary
        self.__kafka_p = AltoProducer("localhost", "9092")

    ### GETers y SETers  ###
    def set_topology_creator(self, tc):
        self.__topology_creator = tc
    def get_topology_creator(self):
        return self.__topology_creator

    def set_topology(self, tc):
        self.__topology = tc.copy()
    def get_topology(self):
        return self.__topology

    def set_topology_writer(self, tw):
        self.__topology_writer = tw
    def get_topology_writer(self):
        return self.__topology_writer

    def set_response(self, re):
        self.__resp = re
    def get_response(self):
        return self.__resp

    def set_api_web_http(self, hp):
        self.__http = hp
    def get_api_web_http(self):
        return self.__http

    ### Statics funtions ###
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
            #pid_name = self.__cyphered_pid(router_id, autonomous_system)
            origin = (autonomous_system, domain_id, area_id, router_id)
            if pid_name not in self.props:
                self.props[pid_name] = []
            self.props[pid_name].append(origin)

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
    
    @staticmethod
    def __get_router_id_from_node_descript_list(self, node_descriptors, key: str):
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

    ### Public funtions ###
    ### RFC7285 functions
    def get_costs_map_by_pid(self, pid):
        #pid = "pid0:" + str(npid)
        #print(pid)
        #print(str(self.__cost_map.keys()))
        if pid in self.__cost_map.keys():
            #print(str(self.pids))
            #print(str(self.cost_map))
            #return self.resp.crear_respuesta("filtro", "networkmap-default", self.vtag, str(self.cost_map[pid]))
            return self.__resp.crear_respuesta("filtro", "costmap-filtered", 0000, str({pid:self.__cost_map[pid]}))
        else:
            return "404: Not Found"

    def get_properties(self, endpoint):
        #return str(self.bf.session.q.nodeProperties().answer().frame())
        pid = self.__endpoints.get(endpoint)
        if pid:
            return str(pid)
        else:
            return "Endpoint not valid"

    def get_endpoint_costs(self, endpoint):
        pid = self.__endpoints.get(endpoint)
        #print(pid)
        if pid:
            return self.get_costs_map_by_pid(pid["pid"])
        else:
            return "Endpoint not valid"
        #return "Implementation in proccess. Sorry dude"

    def get_maps(self):
        return ('{"pids_map":' + self.get_net_map() + ', "costs_map":' + self.get_costs_map() + '}')

    def get_costs_map(self):
        #return self.resp.crear_respuesta("cost-map", "networkmap-default", self.vtag, str(self.cost_map))
        cm = self.__filter_cost_map(1)
        return self.__resp.crear_respuesta("cost-map", "networkmap-default", 0000, str(cm))

    def get_net_map(self):
        #return self.resp.crear_respuesta("pid-map", "networkmap-default", self.vtag, str(self.pids))
        nm = self.__filter_net_map(1)
        return self.__resp.crear_respuesta("pid-map", "networkmap-default", 0000, str(nm))

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

    ### Private funtions ###
    def  __filter_cost_map(self, filter_id):
        '''
            in this first version, the only filter we will do is the securoty filter.
            In this case, first we will evaluate the selected criteria. The nodes that fit
            will be included in the list of keys for the new dictionary.
            Once we have filtered the nodes, we will build the cost map with the nodes selected.
        '''
        filtrado ={}
        try:
            for pid in self.__cost_map.keys():
                if self.__is_client_net(pid) or self.__is_border_node(pid):
                    filtrado[pid] = {}
            print("Claves del cost map:", filtrado.keys())
            for pid in filtrado.keys():
                for pid2 in self.__cost_map[pid].keys():
                    if pid2 in filtrado.keys():
                        filtrado[pid][pid2] = self.__cost_map[pid][pid2]
        except:
            print("Error en el filtrado del mapa de costes")
            return {}
        
        return filtrado

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

    def __filter_net_map(self, filter_id):
        '''
            in this first version, the only filter we will do is the securoty filter.
            In this case, we will evaluate the selected criteria. The nodes that fit
            will be included in the returned net map.
        '''
        filtrado ={}
        for pid in self.__net_map.keys():
            if self.__is_client_net(pid) or self.__is_border_node(pid):
                filtrado[pid] = self.__net_map[pid]
        return filtrado


    def __cyphered_pid(self, router, asn):
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
        return ('pid%d:%s:%d' % (asn, hash_r.hexdigest()[:32], tsn))



    def __compute_netmap(self, asn, redes):
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
            #pid = 'pid%d:%s' % (asn, self.__get_hex_id(router))
            pid = self.__cyphered_pid(router, asn)
            if len(ipv4):
                if pid not in self.__net_map.keys():
                    self.__net_map[pid] = {}
                    #self.__net_map[pid]['ipv4'] = [] 
                #self.__net_map[pid]["ipv4"] = ipv4
                self.__net_map[pid]['ipv4'] = ipv4
            if len(ipv6):
                self.__net_map[pid]["ipv6"] = ipv6
    
    def __compute_costmap(self, asn, topology):
        # shortest_paths is a dict by source and target that contains the shortest path length for
        # that source and destination
        shortest_paths = dict(networkx.shortest_paths.all_pairs_dijkstra_path_length(topology))
        for src, dest_pids in shortest_paths.items():
            #src_pid_name = 'pid%d:%s' % (asn, self.__get_hex_id(src))
            src_pid_name = self.__cyphered_pid(src, asn)
            if src_pid_name not in self.__cost_map:
                self.__cost_map[src_pid_name] = {}
            for dest_pid, weight in dest_pids.items():
                #dst_pid_name = 'pid%d:%s' % (asn, self.__get_hex_id(dest_pid))
                dst_pid_name = self.__cyphered_pid(dest_pid, asn)
                #if src_pid_name not in self.__cost_map:
                #    self.__cost_map[src_pid_name] = {}
                self.__cost_map[src_pid_name][dst_pid_name] = weight

    def __compute_pid_endpoint(self, endpoint):
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

    def manage_updates(self):
        # Thread creation
        tp_thread = TopologyUpdateThread(self.__topology_creator)
        tp_thread.start()
        #api_thread = TopologyExpoThread(self)
        #self.h_thread.start()
        #api_thread.run()
        while True:
            timest, asn, pids, topology = tp_thread.run()
            if asn != '': 
                self.__compute_costmap(int(asn), topology)
                self.__compute_netmap(int(asn), pids)
                self.evaluate_endpoints()
                #self.topology_writer.write_same_ips(self.router_ids)
                self.__topology_writer.write_pid_file(self.__filter_net_map(1))
                self.__topology_writer.write_cost_map(self.__filter_cost_map(1))
                #print(self.__cost_map)
                #print(self.__net_map)
                #print("")
                #print(self.__endpoints)
                #print(self.get_endpoint_costs("3.3.3.2"))
                self.__kafka_p.envio_alto('alto-costes', self.get_costs_map(), 0)
                self.__kafka_p.envio_alto('alto-pids', self.get_net_map(), 0)

        #self.__http.detener()

    def evaluate_endpoints(self):
        with open('/root/cdn-alto/alto-tid/endpoints/properties.json', 'r') as source:
            jason = source.read()
            jason = jason.replace('\t', '').replace('\n', '').replace("'", '"').strip()
            users = json.loads(str(jason))
            for user in users["users"]:
                user["pid"] = self.__compute_pid_endpoint(user["ipv4"][0])
                #user["pid"] = ''
                #print(str(user))
                self.__endpoints[user["ipv4"][0]]=user


### Aux clases ###
class TopologyUpdateThread(threading.Thread):

    def __init__(self, topo_manager):
        threading.Thread.__init__(self)
        self.__tp_mng = topo_manager

    def run (self):
        t,a,p,c = self.__tp_mng.manage_bgp_speaker_updates()
        #t,a,p,c = self.__tp_mng.manage_updates()
        return t,a,p,c

### Aux clases ###
class TopologyExpoThread(threading.Thread):

    def __init__(self, a):
        threading.Thread.__init__(self)
        self.alto = a

    def run (self):
        self.alto.get_api_web_http().run()



if __name__ == "__main__":
    alto = AltoCore(TopologyCreator(),'')
    alto.manage_updates()
