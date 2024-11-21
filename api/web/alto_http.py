#!/usr/bin/env python3
# © 2024 Telefónica Innovación Digital
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import socket
import json
from urllib.parse import urlparse, parse_qs

ERRORES = {"sintax": "E_SYNTAX", "campo": "E_MISSING_FIELD", "tipo": "E_INVALID_FIELD_TYPE", "valor": "E_INVALID_FIELD_VALUE"}

class AltoHttp:

    def __init__(self, a, ip="127.0.0.1", port=8080):
        self.alto = a
        self.port = port
        self.ip = ip
        self.routes = {
            '/' : self.home,
            '/directory' : self.api_directory,
            '/networkmap' : self.api_pids,
            '/costmap' : self.api_costs,
            '/maps' : self.api_maps,
            '/endpoints' : self.api_endpoint_costs,
            '/all' : self.api_all,
            '/best' : self.api_shortest,
            '/costmap/filter' : self.api_costs_by_pid,
            '/costcalendar' : self.api_cost_calendar,
            '/get-topology' : self.api_topology
        }

    ####################################
    ##          APIs functions        ##
    ####################################

    def run(self):
        '''
            Creates the API using TCP sockets and executes the functionality workflow.
            Nor imputs neither outputs.
        '''
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.ip, self.port))
            s.listen(5)
            print(f"API running on http://{self.ip}:{self.port}/")

            while True:
                conn, addr = s.accept()
                with conn:
                    try:
                        data = conn.recv(1024).decode('utf-8')
                        if data:
                            method, path, body = data.split(' ', 2)
                            path = urlparse(path).path
                            print("PATH:", path)
                            path, params = self.parse_params(path)
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
        if path.startswith('/costmap/filter/'):
            params['pid'] = path.split('/')[3]
            path = "/costmap/filter"
        elif path.startswith('/qkd-properties/') or path.startswith('/endpoints/'):
            params['pid'] = path.split('/')[2]
            path = "/"+path.split('/')[1]
        elif path.startswith('/all/') or path.startswith('/best/'):
            params['a'] = path.split('/')[2]
            params['b'] = path.split('/')[3]
            path = "/"+path.split('/')[1]
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

    # Root request.
    ##################
    # TO BE UPDATED  #
    ##################
    def home(self, method, params):
        '''
            Root request. Returns a service list.
            Imput:
                method: GET method. Otherwhise it return a 404 error.
        '''
        if method == 'GET':
            return self.build_response(200, {
                "message": "ALTO PoC's API",
                "services": [
                    {"route": "/networkmap", "methods": ["GET", "POST"]},
                    {"route": "/costmap", "methods": ["GET", "POST"]},
                    {"route": "/maps", "methods": ["GET", "POST"]},
                    {"route": "/endpoints/<string:pid>", "methods": ["GET"]},
                    {"route": "/properties", "methods": ["POST"]},
                    {"route": "/qkd-properties/<string:pid>", "methods": ["GET"]},
                    {"route": "/all/<string:a>/<string:b>", "methods": ["GET"]},
                    {"route": "/best/<string:a>/<string:b>", "methods": ["GET"]},
                    {"route": "/costmap/filter/<string:pid>", "methods": ["GET"]},
                    {"route": "/costcalendar", "methods" : ["GET"]},
                    {"route": "/get-topology", "method" : ["GET"]}
                ]
            })
        else:
            return self.build_response(400, {"ERROR": ERRORES["sintax"], "syntax-error": "Method not valid. Required a POST request."})

    
    ###################################
    ##  Services defined in RFC 7285 ##
    ###################################
    
    # Filtered Cost Map.
    # To be migrated to a POST method.
    def api_costs_by_pid(self, method, params):
        ''' 
            Filtered CostMap where the PID is used as method to filter.
        '''
        if method == 'GET':
            pid = params.get('pid', None)
            if pid is None:
                return self.build_response(400, {"ERROR": ERRORES["valor"], "syntax-error": "PID not found."})
            if not isinstance(pid, str):
                return self.build_response(400, {"ERROR": ERRORES["tipo"], "syntax-error": "The PID type is incorrect. We need a string."})
            return self.build_response(200, self.alto.get_costs_map_by_pid(pid))
        else:
            return self.build_response(400, {"ERROR": ERRORES["sintax"], "syntax-error": "Method not valid. Required a POST request."})            

    # Endpoint Cost Service.
    # To be migrated to a POST method.
    def api_endpoint_costs(self, method, params):
        '''
            Receives an ENDPOINT PID and returns the cost to reach to it from the rest of Endpoints.
        '''
        pid = params.get('pid', None)
        if pid is None:
            return self.build_response(400, {"ERROR": ERRORES["valor"], "syntax-error": "PID not found."})
        if not isinstance(pid, str):
            return self.build_response(400, {"ERROR": ERRORES["tipo"], "syntax-error": "The PID type is incorrect. We need a string."})
        return self.build_response(200, self.alto.get_endpoint_costs(pid))

    # Cost Map and Network Map service. Returns both in one request.
    def api_maps(self, method, params):
        if method == 'GET':
            return self.build_response(200, self.alto.get_maps())
        elif method == 'POST':
            d = params.get('data', None)
            if d is None:
                return self.build_response(400, {"ERROR": ERRORES["valor"], "syntax-error": "Body not found."})
            data = json.loads(d)
            filter = data.get('filter', "")
            if filter == "":
                return self.build_response(400, {"ERROR": ERRORES["campo"], "syntax-error": "Properties field missing."})
            return self.build_response(200, self.alto.get_maps(filter))

    # Cost Map service and Filtered Cost Map Service.
    # To be migrated to Filtered API Cost.
    def api_costs(self, method, params):
        if method == 'GET':
            return self.build_response(200, self.alto.get_costs_map())
        elif method == 'POST':
            d = params.get('data', None)
            if d is None:
                return self.build_response(400, {"ERROR": ERRORES["valor"], "syntax-error": "Body not found."})
            data = json.loads(d)
            filter = data.get('filter', "")
            node = data.get('node', "")
            if filter != "":
                return self.build_response(200, self.alto.get_maps(filter))
            if node != "":
                return self.build_response(200, self.alto.get_costs_map_by_pid(node))
            return self.build_response(400, {"ERROR": ERRORES["campo"], "syntax-error": "Properties field missing. Property fields: node and/or filter"})

    # Network Map Service.
    def api_pids(self, method, params):
        if method == 'GET':
            return self.build_response(200, self.alto.get_net_map())
        elif method == 'POST':
            d = params.get('data', None)
            if d is None:
                return self.build_response(400, {"ERROR": ERRORES["valor"], "syntax-error": "Body not found."})
            data = json.loads(d)
            filter = data.get('filter', "")
            return self.build_response(200, self.alto.get_maps(filter))

    # IRD Service.
    def api_directory(self, method, params):
        return self.build_response(200, self.alto.get_directory())

    # Endpoint properties Service.
    def api_properties(self, method, params):
        pid = params.get('pid', None)
        if pid is None:
            return self.build_response(400, {"ERROR": ERRORES["valor"], "syntax-error": "PID not found."})
        if not isinstance(pid, str):
            return self.build_response(400, {"ERROR": ERRORES["tipo"], "syntax-error": "The PID type is incorrect. We need a string."})
        if method == 'POST':
            d = params.get('data', None)
            if d is None:
                return self.build_response(400, {"ERROR": ERRORES["valor"], "syntax-error": "Body not found."})
            data = json.loads(d)
            properties = data.get('properties', [])
            if properties == []:
                return self.build_response(400, {"ERROR": ERRORES["campo"], "syntax-error": "Properties field missing."})
            pid = data.get('pid', "")
            if pid == "":
                return self.build_response(400, {"ERROR": ERRORES["campo"], "syntax-error": "PID field missing."})
            if not isinstance(pid, str):
                return self.build_response(400, {"ERROR": ERRORES["tipo"], "syntax-error": "The PID type is incorrect. We need a string."})
            return self.build_response(200, self.alto.get_properties(pid, properties))
        else:
            return self.build_response(400, {"ERROR": ERRORES["sintax"], "syntax-error": "Method not valid. Required a POST request."})


    ###################################
    ##          Ampliations          ##
    ###################################    
        
    def api_all(self, method, params):
        '''
            Receiving two PIDs returns all disyunts paths that connect them.
        '''
        a = params.get('a', None)
        b = params.get('b', None)
        if a is None or b is None:
            return self.build_response(400, {"ERROR": ERRORES["valor"], "syntax-error": "Two PIDs are needed."})
        if not isinstance(a, str) or not isinstance(b, str):
            return self.build_response(400, {"ERROR": ERRORES["tipo"], "syntax-error": "The PID type is incorrect. We need two strings."})
        return self.build_response(200, self.alto.parseo_yang(str(self.alto.all_maps(a, b)), "all-paths"))

    def api_shortest(self, method, params):
        '''
            Receiving two network Nodes, returns the shortest path between them.
        '''
        a = params.get('a', None)
        b = params.get('b', None)
        if a is None or b is None:
            return self.build_response(400, {"ERROR": ERRORES["valor"], "syntax-error": "Two PIDs are needed."})
        if not isinstance(a, str) or not isinstance(b, str):
            return self.build_response(400, {"ERROR": ERRORES["tipo"], "syntax-error": "The PID type is incorrect. We need two strings."})
        return self.build_response(200, self.alto.shortest_path(a, b))
    
    
    def api_cost_calendar(self, method, params):
        # FORMAT OF COST_CALENDAR_START_TIME Y PID
        #node --> 5.5.5.6
        #cost_calendar_start_time --> 2024, 1, 25, 10, 10, 20 # year, month, day, hour, minutes, seconds
        #cost_calendar_start_time_tuple = tuple(map(int, cost_calendar_start_time.split(',')))
        return self.build_response(200, self.alto.get_costcalendar())


    def api_topology(self, method, params):
        return self.build_response(200, self.alto.get_topology())

    ####################################
    ##      Sanitize functions        ##
    ####################################

    def sanitize_input_POST(self, texto):
        '''
        Characters acepted in the input: a-zA-Z0-9.{}[]",: -
        '''
        texto_sano = str(texto).replace('#', '').replace('--', '').replace("'", "").replace("//", "").replace('_', '').replace('<', '').replace('>', '').replace('&', '').replace('%', '')
        return texto_sano

    def sanitize_input_GET(self, texto):
        '''
        Characters acepted in the input: a-zA-Z0-9.:
        '''
        texto_sano = str(texto).replace('#', '').replace('--', '').replace("'", "").replace("//", "").replace('_', '').replace('<', '').replace('>', '').replace('&', '').replace('%', '').replace("{", '').replace("}", "").replace('"', "").replace("-", "")
        return texto_sano
