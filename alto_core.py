#!/usr/bin/env python3

# Import section
import threading
import json
import networkx

# Internals imports
from topology_maps_generator import TopologyCreator
from topology_writer import TopologyFileWriter
from parsers.yang_alto import RespuestasAlto
from api.web.alto_http import AltoHttp

# Global information section



# ALTO class
class AltoCore:
    
    def __init__(self, topo_manager, api):
        self.__topology_creator = topo_manager
        self.__topology_writer = TopologyFileWriter('./maps')
        self.__resp = RespuestasAlto()
        self.__topology = networkx.DiGraph()
        self.__pids = {}
        self.__cost_map = {}
        self.__http = AltoHttp(self)
        self.h_thread = threading.Thread(target=self.__http.run)

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
        #print(str(self.pids))
        if pid in self.cost_map.keys():
            #print(str(self.pids))
            #print(str(self.cost_map))
            #return self.resp.crear_respuesta("filtro", "networkmap-default", self.vtag, str(self.cost_map[pid]))
            return self.resp.crear_respuesta("filtro", "networkmap-default", 0000, str(self.cost_map[pid]))
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
        #return self.resp.crear_respuesta("cost-map", "networkmap-default", self.vtag, str(self.cost_map))
        return self.resp.crear_respuesta("cost-map", "networkmap-default", 0000, str(self.cost_map))

    def get_pids(self):
        #return self.resp.crear_respuesta("pid-map", "networkmap-default", self.vtag, str(self.pids))
        return self.resp.crear_respuesta("pid-map", "networkmap-default", 0000, str(self.pids))

    def get_directory(self):
        return self.resp.indice()

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

    ### Private funtions ###
    def __compute_costmap(self, asn, topology):
        # shortest_paths is a dict by source and target that contains the shortest path length for
        # that source and destination
        shortest_paths = dict(networkx.shortest_paths.all_pairs_dijkstra_path_length(topology))
        for src, dest_pids in shortest_paths.items():
            src_pid_name = 'pid%d:%s' % (asn, self.__get_hex_id(src))
            for dest_pid, weight in dest_pids.items():
                dst_pid_name = 'pid%d:%s' % (asn, self.__get_hex_id(dest_pid))
                if src_pid_name not in self.__cost_map:
                    self.__cost_map[src_pid_name] = {}
                self.__cost_map[src_pid_name][dst_pid_name] = weight


    def manage_updates(self):
        # Thread creation
        tp_thread = TopologyUpdateThread(self.__topology_creator)
        tp_thread.start()
        #api_thread = TopologyExpoThread(self)
        self.h_thread.start()
        #api_thread.run()
        while True:
            timest, asn, pids, topology = tp_thread.run()
            self.__compute_costmap(int(asn), topology)
            #self.topology_writer.write_same_ips(self.router_ids)
            self.__topology_writer.write_pid_file(self.__pids)
            self.__topology_writer.write_cost_map(self.__cost_map)
            print(self.__cost_map)
        self.__http.detener()



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
        self.alto = a

    def run (self):
        self.alto.get_api_web_http().run()





if __name__ == "__main__":
    alto = AltoCore(TopologyCreator(),'')
    alto.manage_updates()

