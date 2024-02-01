#!/usr/bin/env python3
# © 2024 Telefónica Innovación Digital, All rights reserved


import json
from datetime import datetime

COSTE = "routingcost"

class RespuestasAlto:

    def __init__(self):
        self.algo=0
        self.tipos={"directory": "application/alto-directory+json", "networkmap": "application/alto-networkmap+json",
                    "networkmapfilter": "application/alto-networkmapfilter+json","costmap": "application/alto-costmap+json",
                    "costmapfilter": "application/alto-costmapfilter+json","endpointprop": "application/alto-endpointprop+json",
                    "endpointpropparams": "application/alto-endpointpropparams+json","endpointcost": "application/alto-endpointcost+json",
                    "endpointcostparams": "application/alto-endpointcostparams+json","error": "application/alto-error+json"}

    def crear_respuesta(self, tipo, ctipo, rid, vtag, contenido):
        
        if tipo == "cost-map":
            return self.respuesta_costes(ctipo, rid, vtag, contenido)
        elif tipo == "pid-map":
            return self.respuesta_pid(ctipo, rid, vtag, contenido)
        elif tipo == "filtro":
            return self.respuesta_filtro(ctipo, rid, vtag, contenido)
        elif tipo == "prop":
            return self.respuesta_prop(ctipo, rid, vtag, contenido)
        elif tipo == "endpoint-costs":
            return self.respuestar_endpoint_costs(ctipo, rid, vtag, contenido)
        else:
            return ""


    def respuesta_costes(self, tipo, rid, vtag, costmap):
        '''
        Return a json-YANG structure from a raw costmap.
        Parameters: 
            type:    type of map required.
            rid:     resource ID of the network map related
            vtag:    timestamp of the last network map
            costmap: dict of PIDs and costs
        '''
        cabecera = {'Content-Type' : self.tipos[tipo]}
        meta = {'dependent-vtags': [{'resource-id': str(rid), 'tag': str(vtag)}], 'cost-type':{'cost-mode':'numerical','cost-metric':COSTE}}
        cuerpo = {'cost-map' : costmap}
        #resp = "{'meta':{'Content-Type':'" + self.tipos[tipo] + "','dependent-vtag':[{'resource-id':'" + str(rid) + "','tag': '" + str(vtag) +"'}],'cost-type': {'cost-mode' : 'numerical','cost-metric' : 'routingcost'}},'cost-map':" + str(costmap) + "}"
        #return "{'header':" + str(cabecera) + ", 'meta':"+ str(meta) + ", 'cost-map': " + str(costmap) + '}'
        return "{'meta':"+ str(meta) + ", 'cost-map': " + str(costmap) + '}'


    def respuesta_pid(self, tipo, rid, vtag, netmap):
        '''
        Return a json-YANG structure from a raw networkmap.
        Parameters:
            type:    type of map required.
            rid:     resource ID of the network map
            vtag:    timestamp of the  network map
            netmap: dict of PIDs and network reachables
        '''
        cabecera = {'Content-Type' : self.tipos[tipo]}
        meta = {'vtag': {'resource-id': str(rid), 'tag': str(vtag)}}
        cuerpo = {"network-map" : netmap}
        #resp = "{'meta' : {'type':'alto-networkmap+json','vtag' : [{'resource-id':'" + str(rid) + "','tag':'" + str(vtag) +"'}]},'network-map':" + str(netmap) + "}"
        #return "{'header':" + str(cabecera) + ", 'meta':"+ str(meta) + ", 'network-map': " + str(netmap) + '}
        return "{'meta':"+ str(meta) + ", 'network-map': " + str(netmap) + '}'

    def respuesta_prop(self, tipo, rid, vtag, contenido):
        cabecera = {'Content-Type' : self.tipos[tipo]}
        meta = {'dependent-vtags': [{'resource-id': str(rid), 'tag': str(vtag)}]}
        cuerpo = {'endpoint-properties' : contenido}
        #resp = "{'meta':{'Content-Type':'" + self.tipos[tipo] + "','dependent-vtag':[{'resource-id':'" + str(rid) + "','tag': '" + str(vtag) +"'}],'cost-type': {'cost-mode' : 'numerical','cost-metric' : 'routingcost'}},'cost-map':" + str(costmap) + "}"    
        return "{'header':" + str(cabecera) + ", 'meta':"+ str(meta) + ", 'cost-map': " + str(contenido) + '}'
    
    def respuestar_endpoint_costs(self, rid, vtag, costmap):
        return ""

    def indice(self): 
        return '''{"meta" : {"cost-types": {"num-routing": {"cost-mode" : "numerical","cost-metric": "routingcost","description": "My default"},"num-hop": {"cost-mode" : "numerical","cost-metric": "hopcount"},"ord-routing": {"cost-mode" : "ordinal","cost-metric": "routingcost"},"ord-hop": {"cost-mode" : "ordinal","cost-metric": "hopcount"}}},"resources" : {"network-map" : {"uri" : "http://localhost:5000/networkmap","media-type" : "application/alto-networkmap+json","uses": [ "networkmap-default" ]},"cost-map" : {"uri" : "http://localhost:5000/costmap","media-type" : "application/alto-costmap+json","capabilities" : {"cost-constraints" : true,"cost-type-names" : [ "num-routing", "num-hop","ord-routing", "ord-hop" ]},"uses": [ "networkmap-default" ]},"filtered-costs-map" : {"uri" : "http://localhost:5000//costmap/filter/<string:pid>","media-type" : "application/alto-networkmap+json","accepts" : "application/alto-networkmapfilter+json","uses": [ "networkmap-default" ]},"both-map" : {"uri" : "http://localhost:5000//maps","media-types" : ["application/alto-networkmap+json","application/alto-costmap+json"] ,"uses": [ "networkmap-default" ]}}}'''


