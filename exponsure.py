#!/usr/bin/env python3


import os
import sys
import json
import threading
import flask
from time import sleep
#sys.path.append('cdn-alto/')
from bgp.manage_bgp_speaker import ManageBGPSpeaker
#sys.path.append('alto-ale/')
from alto_core import TopologyCreator
from alto_core import TopologyFileWriter
#from modulos.topology_bgp import TopologyBGP
#from modulos.topology_ietf import TopologyIetf



class HiloHTTP(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        #self.tc = topology_creator
        #Código global
        #app = flask.Flask(__name__)
        #app.config["DEBUG"] = True

    def run (self):
        alto.manage_bgp_speaker_updates()
        #alto.mailbox(8888)
        #self.app.run()

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
    cuerpo = flask.jsonify(alto.get_costs_map_by_pid(pid))
    res = flask.Response(cuerpo, mimetype="application/alto-costmapfilter+json")
    res.headers["Content-Type"] = "application/alto-costmapfilter+json"
    return res

#Endpoint Property Service
@app.route('/properties/<string:pid>', methods=['GET'])
def api_properties(pid):
    cuerpo = flask.jsonify(alto.get_properties(pid))
    res = flask.Response(cuerpo, mimetype="application/alto-endpointprop+json")
    res.headers["Content-Type"] = "application/alto-endpointprop+json"
    return res

#Endpoint Cost Service
@app.route('/costmap/<string:pid>', methods=['GET'])
def api_endpoint_costs(pid):
    cuerpo = flask.jsonify(alto.get_endpoint_costs(pid))
    res = flask.Response(cuerpo, mimetype="application/alto-endpointcost+json")
    res.headers["Content-Type"] = "application/alto-endpointcost+json"
    return res

#Map Service
@app.route('/maps', methods=['GET'])
def api_maps():
    cuerpo = flask.jsonify(alto.get_maps())
    res = flask.Response(cuerpo, mimetype="application/alto-networkmapcostmap+json")
    res.headers["Content-Type"] = "application/alto-networkmapcostmap+json"
    return res

#Network Map service
@app.route('/costmap', methods=['GET'])
def api_costs():
    cuerpo = flask.jsonify(alto.get_costs_map())
    res = flask.Response(cuerpo, mimetype="application/alto-costmap+json")
    res.headers["Content-Type"] = "application/alto-costmap+json"
    return res

@app.route('/networkmap', methods=['GET'])
def api_pids():
    cuerpo = flask.jsonify(alto.get_pids())
    res = flask.Response(cuerpo, mimetype="application/alto-networkmap+json")
    res.headers["Content-Type"] = "application/alto-networkmap+json"
    return res

@app.route('/directory', methods=['GET'])
def api_directory():
    cuerpo = flask.jsonify(alto.get_directory())
    res = flask.Response(cuerpo, mimetype="application/alto-directory+json")
    res.headers["Content-Type"] = "application/alto-directory+json"
    return res


###################################
##                               ##
#           Ampliations           #
##                               ##
###################################


#All possible paths between A and B without any common node
@app.route('/all/<string:a>/<string:b>', methods=['GET'])
def api_all(a,b):
    return flask.jsonify(alto.parseo_yang(str(alto.all_maps(alto.topology, a, b)),"all-paths"))

#Best path between A and B
@app.route('/best/<string:a>/<string:b>', methods=['GET'])
def api_shortest(a,b):
    return flask.jsonify(str(alto.shortest_path(a, b)))

if __name__ == '__main__':
    #Creation of ALTO modules
    '''modules={}
    modules['bgp'] = TopologyBGP(('localhost',8888))
    #modules['ietf'] = TopologyIetf(('localhost',8081))
    alto = TopologyCreator(modules, 0)
    hilos = alto.lanzadera()

    hilo = HiloHTTP()
    hilo.start()
    hilos.append(hilo)
    sleep(30)
    alto.get_costs_map()
    '''

speaker_bgp = ManageBGPSpeaker()
exabgp_process = speaker_bgp.check_tcp_connection()
alto = TopologyCreator(exabgp_process)
hilo = HiloHTTP()
hilo.start()
#app.run(host='192.168.165.193', port=8080)
app.run()
