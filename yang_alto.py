#!/usr/bin/env python3

import json
from datetime import datetime


class RespuestasAlto:

    def __init__(self):
        self.algo=0


    def crear_respuesta(self, tipo, rid, vtag, contenido):
        
        if tipo == "cost-map":
            return self.respuesta_costes(rid, vtag, contenido)
        elif tipo == "pid-map":
            return self.respuesta_pid(rid, vtag, contenido)
        elif tipo == "filtro":
            return self.respuesta_filtro(rid, vtag, contenido)
        elif tipo == "prop":
            return self.respuesta_prop(rid, vtag, contenido)
        elif tipo == "endpoint-costs":
            return self.respuestar_endpoint_costs(rid, vtag, contenido)
        else:
            return ""


    def respuesta_costes(self, rid, vtag, costmap):
        '''
        Return a json-YANG structure from a raw costmap.
        Parameters: 
            rid:     resource ID of the network map related
            vtag:    timestamp of the last network map
            costmap: dict of PIDs and costs
        '''
        
        resp = "{'meta':{'type':'alto-costmap+json','dependent-vtag':[{'resource-id':'" + str(rid) + "','tag': '" + str(vtag) +"'}],'cost-type': {'cost-mode' : 'numerical','cost-metric' : 'routingcost'}},'cost-map':" + str(costmap) + "}"
        
        return resp


    def respuesta_pid(self, rid, vtag, netmap):
        '''
        Return a json-YANG structure from a raw networkmap.
        Parameters:
            rid:     resource ID of the network map
            vtag:    timestamp of the  network map
            netmap: dict of PIDs and network reachables
        '''
        
        resp = "{'meta' : {'type':'alto-networkmap+json','vtag' : [{'resource-id':'" + str(rid) + "','tag':'" + str(vtag) +"'}]},'network-map':" + str(netmap) + "}"
        
        return resp


    def respuesta_filtro(self, rid, vtag, fitro, mapa):
        return ""
    def respuesta_prop(self, rid, vtag, contenido):
        return ""
    def respuestar_endpoint_costs(self, rid, vtag, costmap):
        return ""

    def indice(self):
        return '''{"meta" : {"cost-types": {"num-routing": {"cost-mode" : "numerical","cost-metric": "routingcost","description": "My default"},"num-hop": {"cost-mode" : "numerical","cost-metric": "hopcount"},"ord-routing": {"cost-mode" : "ordinal","cost-metric": "routingcost"},"ord-hop": {"cost-mode" : "ordinal","cost-metric": "hopcount"}}},"resources" : {"network-map" : {"uri" : "http://localhost:5000/networkmap","media-type" : "application/alto-networkmap+json","uses": [ "networkmap-default" ]},"cost-map" : {"uri" : "http://localhost:5000/costmap","media-type" : "application/alto-costmap+json","capabilities" : {"cost-constraints" : true,"cost-type-names" : [ "num-routing", "num-hop","ord-routing", "ord-hop" ]},"uses": [ "networkmap-default" ]},"filtered-costs-map" : {"uri" : "http://localhost:5000//costmap/filter/<string:pid>","media-type" : "application/alto-networkmap+json","accepts" : "application/alto-networkmapfilter+json","uses": [ "networkmap-default" ]},"both-map" : {"uri" : "http://localhost:5000//maps","media-types" : ["application/alto-networkmap+json","application/alto-costmap+json"] ,"uses": [ "networkmap-default" ]}}}'''


