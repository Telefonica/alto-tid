#!/usr/bin/env python3
# © 2024 Telefónica Innovación Digital, All rights reserved

import logging
import networkx
from datetime import datetime
from time import sleep
from modulos.alto_module import AltoModule
import socket
import json
from urllib.parse import urlparse, parse_qs


RR_BGP_0 = "50.50.50.1"
#RR_BGP = BGP_INFO['bgp']['ip']
MAX_VAL = 16777214
time_interval_size = 120 #seconds
number_of_intervals = 5
ERRORES = {"sintax": "E_SYNTAX", "campo": "E_MISSING_FIELD", "tipo": "E_INVALID_FIELD_TYPE", "valor": "E_INVALID_FIELD_VALUE"}


class TopologyNDT(AltoModule):

    def __init__(self, mb):
        super().__init__(mb)
        '''        self.ietf_process = 0
        self.props = {}
        self.pids = {}'''
        self.ip="0.0.0.0"
        self.port=9999
        self.topology = networkx.Graph()
        self.cost_map = {}
        self.router_ids = []
        self.list_topologies = []
        self.ts = {}
        self.routes = {
            '/update-expected-topology' : self.api_cost_calendar_cs
        }

        logging.basicConfig(format="%(levelname)s:%(message)s", level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        #timestamp = int(datetime.now().timestamp())
        self.filename = "./logs/alto.log"


    def run(self):
        '''
            Creates the API using TCP sockets and executes the functionality workflow.
            Nor imputs neither outputs.
        '''
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.ip, self.port))
            s.listen(5)
            self.logger.info(f"API running on http://{self.ip}:{self.port}/")
            self.logger.info("Timestamp:\t %s", str(datetime.now()))

            while True:
                conn, addr = s.accept()
                with conn:
                    try:
                        data = conn.recv(32768).decode('utf-8')
                        if data:
                            method, path, body = data.split(' ', 2)
                            path = urlparse(path).path
                            self.logger.info("API Acceded: %s", str(path))
                            self.logger.info("Timestamp:\t %s", str(datetime.now()))
                            path, params = self.parse_params(path)
                            # print("BODY PETICIÓN:\t", body)
                            # print("DATA:\t", data)
                            if body:
                                params['data'] = body.split("\r\n\r\n")[1]
                            print("Parametros:", str(params), "URL:", str(path))
                            response = self.handle_request(method, path, params)
                            conn.sendall(response)
                    except Exception as e:
                        error_response = self.build_response(500, {"ERROR": "E_SERVER_ERROR", "message": str(e)})
                        conn.sendall(error_response)    

    def parse_params(self, path):
        ''' 
            If a GET API has params, this function extracts them.
            Imput:
                Path: URI recived.
            Output:
                Path: Resulting path without params.
                Params: List of params received from the GET request.
        '''
        params = {}
        return path, params

    def handle_request(self, method, path, params): 
        '''
            If the request is associated to an existig route, it returns the functionality.
            Otherwise, it return a 404 error.
            All functions receive the same params to help the standardization of the request.
            Imputs:
                Method: GET/POST.
                Path: filtered path without the parameters.
                Params: params received in the body and/or the URI.
            Output:
                Result of the functionality requested.
        '''       
        if path in self.routes:
            return self.routes[path](method, params)
        else:
            return self.not_found()

    def not_found(self):
        '''
            404 ERROR handler.
        '''
        return self.build_response(404, {"ERROR": ERRORES["sintax"], "syntax-error": "Not Found"})

    def build_response(self, status_code, data):
        '''
            HTTP response handler.
            Imputs:
                Status_code: HTTP Status Code
                Data: information to be sent in the body.
            Output:
                HTTP response.
        '''
        response = f"HTTP/1.1 {status_code}\r\n"
        response += "Content-Type: application/json\r\n"
        response += "\r\n"
        response += json.dumps(data)
        response += "\r\n"
        return response.encode('utf-8')

    
    ### Manager function       
    def manage_topology_updates(self):
        while 1:
            #sleep(15)
            sleep(5)
            self.manage_updates()

    def api_cost_calendar_cs(self, method, params):
        if method == 'POST':
            d = params.get('data', None)
            if d is None:
                return self.build_response(400, {"ERROR": ERRORES["valor"], "syntax-error": "Body not found."})
            print("Info recibida:\t", d)
            data = json.loads(d.replace("'",'"').replace("\n","").replace("\t",""))
            self.logger.debug("Info recibida: %s", str(data))
            # data = request.json
            cost_calendar_start_time = data.get('calendar_start_time', [])
            #cost_calendar_start_time_tuple = tuple(map(int, cost_calendar_start_time.split(',')))
            update_topology = data.get('update_topology', "")
            # print(f"Info received:\t{update_topology}")
            self.manage_updates(cost_calendar_start_time, update_topology)
        return self.build_response(200, {"MESSAGE": "Costcalendar Created"})



    def manage_updates(self, cost_calendar_start_time, update_topology):
        '''
        Receives topology information from the PCE by the Southaband Interface and creates/updates the graphs
        Realizes an iterational analisis, reviewing each network: if two networks are the same but by different protocols, they must to be merged.
        Three attributes on each network: dic[ips], dic[interfaces] and graph[links]
        '''
        if update_topology != "":
            data = {"pids":"","nodes-list": "","costs-list": "","prefixes": "", "topology":update_topology, "start-time":cost_calendar_start_time }
            self.return_info(5,0,1, data)
                        

