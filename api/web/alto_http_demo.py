#!/usr/bin/env python3
# © 2024 Telefónica Innovación Digital, All rights reserved

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
            '/': self.home,
            '/directory': self.api_directory,
            '/networkmap': self.api_pids,
            '/costmap': self.api_costs,
            '/maps': self.api_maps,
            '/endpoints': self.api_endpoint_costs,
            '/properties': self.api_properties,
            '/qkd-properties': self.api_qkd_properties,
            '/all': self.api_all,
            '/best': self.api_shortest,
            '/costmap/filter': self.api_costs_by_pid,
            '/get-bordernode': self.api_bordernode
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
                    if 1:
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
                "services": '''
            ALTO PoC's API
            Services expossed:
            1. Costs map: /costmap ['GET']
            2. Filtered Cost map: /costmap ['POST']                 -> Parameters: Node-ID as "node"
            3. QKD Link Properties: /qkd-properties ['POST']        -> Parameters: QKD Link Properties as "link"
            4. Border Node Information: /get-bordernode ['POST']    -> Parameters: Node-ID as "node"
        '''
            })
        else:
            return self.build_response(400, {"ERROR": ERRORES["sintax"], "syntax-error": "Method not valid. Required a GET request."})

    
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

    # Discretion Ampliation.
    def api_qkd_properties(self, method, params):
        '''
            Particular case of Endpoint Properties Service for QKD networks.
        '''
        if method == 'POST':
            d = params.get('data', None)
            if d == None:
                return self.build_response(400, {"ERROR": ERRORES["valor"], "syntax-error": "Body not found."})
            data = json.loads(d)                            
            pid = data.get('pid', None)
            link = data.get('link', None)
            if (pid is None) and (link is None) :
                return self.build_response(400, {"ERROR": ERRORES["valor"], "syntax-error": "Node-ID/Link-ID not found. Please Provide a field node: Node-ID or link:Link-ID."})
            if link is not None:
                if not isinstance(link, str):
                    return self.build_response(400, {"ERROR": ERRORES["tipo"], "syntax-error": "The Link-ID type is incorrect. We need a string."})
                return self.build_response(200, self.alto.get_qkd_link_properties(link)) 
            elif not isinstance(pid, str):
                return self.build_response(400, {"ERROR": ERRORES["tipo"], "syntax-error": "The PID type is incorrect. We need a string."})
            return self.build_response(200, self.alto.get_qkd_properties(pid))
        return self.build_response(400, {"ERROR": ERRORES["sintax"], "syntax-error": "Method not valid. Required a POST request."})


    # Discretion ampliation
    def api_bordernode(self,method, params):
        '''
            API used to identify which nodes in pur network can connect with external network nodes.
            Federation Use Cases.
        '''
        if method == 'POST':
            d = params.get('data', None)
            if d is None:
                return self.build_response(400, {"ERROR": ERRORES["valor"], "syntax-error": "Body not found."})
            data = json.loads(d)
            node = data.get('node', "")
            if node != "":
                return self.build_response(200, self.alto.get_bordernode(node))
            return self.build_response(400, {"ERROR": ERRORES["campo"], "syntax-error": "Properties field missing. Property fields: node and/or filter"})
        
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
        return self.build_response(200, str(self.alto.shortest_path(a, b)))

    # ### Desire6G ampliation
    # def api_graphs(self, method, params):
    #     '''
    #         Returns the different Compute Nodes with at least N characteristics ad connected by less than s latency.
    #     '''
    #     if method == 'POST':
    #         data = params.get('data', None)
    #         #data = self.sanitize_input_POST(data)
    #         if data is None:
    #             return self.build_response(400, {"ERROR": ERRORES["valor"], "syntax-error": "Missing node PID."})
    #         else:
    #             return self.build_response(200, str(self.alto.desire6g_graphs(data)))
    #     else:
    #         return self.build_response(400,{"ERROR" : ERRORES["sintax"], "syntax-error": "Method not valid. Required a POST request."})


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
