#!/usr/bin/env python3
# © 2024 Telefónica Innovación Digital, All rights reserved
import json
import requests
import hashlib

from time import sleep
from datetime import datetime
from modulos.alto_module import AltoModule
from alto_logger import AltoLogger

DEFAULT_ASN = 0


class TopologyQKD(AltoModule):


    #def __init__(self, mb, ruta="./maps/qkd-topology.json", sdn="192.168.159.205"):
    def __init__(self, mb, ruta="./maps/qkd-topology.json", sdn="10.8.1.90"):
        super().__init__(mb)
        self.topology_file = ruta
        self.topology_file = "./maps/qkd-topology-remote.json"
        self.topology_devices = "./maps/qkd-devices-remote.json"
        self.topology_enlaces = "./maps/qkd-enlaces.json"
        self.sdn_api = sdn
        self.logger = AltoLogger("log/alto")


    # Get Topology
    def get_topology(self, prueba=False):
        try:
            # Si es prueba, lee del archivo local
            if prueba:
                with open(self.topology_file, 'r') as file:
                    data = json.load(file)
            else:
                # Realiza la petición HTTP
                url = "http://" + self.sdn_api + "/webui/qkd/c76135e3-24a8-5e92-9bed-c3c9139359c8/43813baf-195e-5da6-af20-b3d0922e71a7/topology" # "/webui/qkd/topology"
                self.logger.log_message(f"URL:\t{url}")
                response = requests.get(url)
                response.raise_for_status()  # Lanza una excepción si el estatus no es 200
                data = response.json()  # Parsear la respuesta a JSON
                self.logger.log_message(f"Data:\t{data}")
            return data
        except (requests.exceptions.RequestException, json.JSONDecodeError, FileNotFoundError, IOError) as error:
            # Devuelve un diccionario vacío en caso de cualquier error
            self.logger.log_message(f"Error en la ejecución:\t{error}")
            return {}
        
    # Get Devices
    def get_device(self, nodo, prueba=False):
        try:
            # Si es prueba, lee del archivo local
            if prueba:
                with open(self.topology_devices, 'r') as file:
                    nodos = json.load(file)
                    data = nodos[nodo]
                    links = data["qkd_node"]["qkd_links"]["qkd_link"]
            else:
                # Realiza la petición HTTP 
                # URL: http://192.168.159.205/webui/qkd/device/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
                url = "http://" +  self.sdn_api + "/webui/qkd/device/" + str(nodo)
                #print("URL:\t", url)
                response = requests.get(url)
                response.raise_for_status()  # Lanza una excepción si el estatus no es 200
                data = response.json()  # Parsear la respuesta a JSON
                links = data["qkd_links"]
                self.logger.log_message(f"Links obtained:\t{links}")                
            return links
        except (requests.exceptions.RequestException, json.JSONDecodeError, FileNotFoundError, IOError) as E:
            # Devuelve un diccionario vacío en caso de cualquier error
            self.logger.log_message(f"Execution error:\t{E}")
            return {}

    def get_weight(self, link, prueba=False):
        try:
            # Si es prueba, lee del archivo local
            if prueba:
                with open(self.topology_enlaces, 'r') as file:
                    links = json.load(file)
                    data = links[link]
                    peso = data["key_availability"]
            else:
                # Realiza la petición HTTP 
                # URL: http://192.168.159.205/webui/qkd/link/bbbbbbbb-cccc-cccc-cccc-bbbbbbbbbbbb/key_availability
                url = "http://" +  self.sdn_api + "/webui/qkd/link/" + str(link) + "/key_availability"
                #print("URL:\t", url)
                response = requests.get(url)
                response.raise_for_status()  # Lanza una excepción si el estatus no es 200
                data = response.json()  # Parsear la respuesta a JSON
                peso = data["key_availability"]
                self.logger.log_message(f"Link:\t{data}")                
            return peso
        except (requests.exceptions.RequestException, json.JSONDecodeError, FileNotFoundError, IOError) as E:
            # Devuelve un diccionario vacío en caso de cualquier error
            self.logger.log_message(f"Execution error:\t{E}")
            return 0

    ### Manager function
    def manage_topology_updates(self):
        something_changed = 0
        while True:
            sleep(1)
            something_changed = self.manage_updates(something_changed)
            sleep(40)
            
    def manage_updates(self, cambios):
        """
        Reads stdout of process exabgp.  Decoded update messages from exabgp 
        are used to build the network map and cost map.
        :param previous_hash: The hash of the last processed topology file
        :return: The new hash after processing the topology file
        """
        #List of Nodes IDs
        nodos = []
        #Disccionario Nodo-id:prefijos
        prefijos = {}
        #Lista de enlaces
        links = []
        
        d_json = self.get_topology(False)
        self.vtag = hashlib.sha3_384((str(int(datetime.timestamp(datetime.now())*1000000))).encode()).hexdigest()[:64]

        if d_json != {}:
            deluro = str(d_json)
            if cambios != hashlib.sha3_384(deluro.encode()).hexdigest():
                cambios = hashlib.sha3_384(deluro.encode()).hexdigest()
                # Load nodes
                nodos = [ nodo["name"] for nodo in d_json["devices"] ]
                # Load links
                for nodo in nodos:
                    nlinks = self.get_device(nodo, False)
                    for nlink in nlinks:
                        # Pedimos el peso
                        peso = self.get_weight(nlink["link_id"], False)                        
                        local = nlink["local"]["qkd_node"]
                        remote = nlink["remote"]["qkd_node"]
                        link = (local, nlink["remote"]["qkd_node"], peso)
                        # print("Link:\t", link)
                        links.append(link)
                        if local not in prefijos.keys():
                            prefijos[local] = {}
                        prefijos[local][remote] = nlink["local"]["interface"]
                        if remote not in prefijos.keys():
                            prefijos[remote] = {}
                        prefijos[remote][local] = nlink["remote"]["interface"]
                #links = [ (n["source"], n["target"], 1) for n in d_json["links"] ]        
                # Load networks --> Not in this version
                #prefijos = {}
                #print("NODOS:\t", nodos)
                #print("Links:\t", links)
                snodos = str(nodos).replace("'", '"')
                prefijos = str(prefijos).replace("'", '"')
                #slinks = str(links).replace("'", '"').replace("(", "[").replace(")","]")
                #print("SLINKS:\n",slinks)
                self.logger.log_message("Topology loaded")
                data = '{"pids":'+ '""' +',"nodes-list": '+snodos+',"costs-list": '+ str(links) +',"prefixes": '+prefijos+"}"
                self.logger.log_message(f"Data:\t{data}")
                self.return_info(2,0,1, data)
        return cambios
