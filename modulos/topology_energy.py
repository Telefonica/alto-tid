#!/usr/bin/env python3

import networkx
import re
import subprocess

from time import sleep
from modulos.alto_module import AltoModule


DEFAULT_ASN = 1
MAX_VAL = 16777214

class TopologyEnergy(AltoModule):

    def __init__(self, mb, timesleep = 5):
        super().__init__(mb)
        '''        self.ietf_process = 0
        self.props = {}
        self.pids = {}'''
        self.topology = networkx.Graph()
        self.cost_map = {}
        self.routers = []
        self.ts = {}
        self.sleep = timesleep
        self.nodos={"10.95.90.86":{"user":"cisco","pass":"cisco123"},"192.168.27.160":{"user":"admin","pass":"admin1"}}
        #self.links=[["10.95.90.86","192.168.27.160"],]
        
        
    ### Manager function       
    def manage_topology_updates(self):
        while 1:
            #sleep(15)
            sleep(self.sleep)
            self.manage_updates()


    def manage_updates(self):
        '''
        Receives topology information from the PCE by the Southaband Interface and creates/updates the graphs
        Realizes an iterational analisis, reviewing each network: if two networks are the same but by different protocols, they must to be merged.
        Three attributes on each network: dic[ips], dic[interfaces] and graph[links]
        '''
        energia = {}
        for nodo in self.nodos:
            energia[nodo] = self.extraer_energia(nodo)
            self.routers.append(nodo)
            
        #for enlace in self.links:
        #      self.topology.add_edge(enlace[0], enlace[1], (energia[enlace[0]] + energia[enlace[1]]))  
        snodos = str(self.routers).replace("'", '"')
        data = '{"pids":'+'{}'+',"nodes-list": '+snodos+',"costs-list": '+str(energia)+',"prefixes": '+'{}'+"}"
        self.return_info(3,0,1, data)
                        

    ### Private funtions ###
    def extraer_energia(self, ip):
        #print(ip)
        try:
            proceso = subprocess.Popen(["./extraer_energia.sh",self.nodos[ip]["pass"],self.nodos[ip]["user"],ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            salida, errores = proceso.communicate()
            #print("salida", salida)
            watts = re.search("\d+",salida.decode()).group(0)
            proceso = subprocess.Popen(["./extraer_interfaces.sh"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            salida, errores = proceso.communicate()
            interfaces = salida.decode().split("\n")
            #estados = [up, down, administratively down]
            estados = [0,0,0]
            costes = [20,7.9,0.1]
            for interf in interfaces:
                if interf.find('is up') != -1:
                    #print("is up\t", interf)
                    estados[0] = estados[0] + 1
                elif interf.find('is down') != -1:
                    #print("is down\t", interf)
                    estados[1] = estados[1] + 1
                else:
                    #print("is administratively down\t:", interf)
                    estados[2] = estados[2] + 1
            coste = 0
            total = len(interfaces)
            for v1,v2 in zip(costes,estados):
                coste = coste + (v1*v2)
            valor = (float(watts) - coste)/total + costes[0]
            #print(estados[0], estados[1], estados[2])
            #print("valor - watts - coste - total")
            #print(valor, watts, coste, total)
            return round(valor, 3)
            
        except:
            return -1