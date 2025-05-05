#!/usr/bin/env python3
# © 2024 Telefónica Innovación Digital, All rights reserved
''' Moudle to manage the ALTO HTTP API.
It creates a TCP socket and listens for incoming requests.
It handles the requests and returns the response.
It uses the AltoModule class to manage the ALTO module.
It uses the AltoLogger class to log the messages.
It uses the AltoGui class to visualize the topology.'''

import socket
import json
from urllib.parse import urlparse
import datetime
from sys import path
import os

import requests

from alto_logger import AltoLogger
from api.web.alto_gui import AltoGui

current_dir = os.path.dirname(os.path.abspath(__file__))
target_dir = os.path.normpath(os.path.join(current_dir, '../../'))
path.insert(0, target_dir)


ERRORES = {"sintax": "E_SYNTAX", "campo": "E_MISSING_FIELD",
           "tipo": "E_INVALID_FIELD_TYPE", "valor": "E_INVALID_FIELD_VALUE"}

class AltoHttp:
    '''
        Class to manage the HTTP API.
        It creates a TCP socket and listens for incoming requests.
        It handles the requests and returns the response.
        It uses the AltoModule class to manage the ALTO module.
        It uses the AltoLogger class to log the messages.
        It uses the AltoGui class to visualize the topology.
    '''

    def __init__(self, a, ip="127.0.0.1", port=8888):
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
            '/get-bordernode': self.api_bordernode,
            '/federation-api': self.api_federation,
        }
        self.logger = AltoLogger("log/alto")
        # Visualización gráfica de la topología si está disponible
        self.app = None
        try:
            self.gui = AltoGui(self.alto)
            self.app = self.gui.app
            print("GUI initialized")
        except Exception as e:
            self.logger.log_message(f"No se pudo inicializar la GUI de red: {e}")

        self.created_services = []     # List for storing created services

        print("Dash app initialized")
        self.requests = []
        self.federados = ["192.168.159.83:9998"]
        #self.sdn = "192.168.159.205:80"
        self.sdn = "10.8.0.90:80"
        self.logger.log_message("Federation API initialized")


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
            mensaje = f"API running on http://{self.ip}:{self.port}/"
            self.logger.log_message(mensaje)

            while True:
                conn, _ = s.accept()
                with conn:
                    try:
                        data = conn.recv(1024).decode('utf-8')
                        if data:
                            method, npath, body = data.split(' ', 2)
                            npath = urlparse(npath).path
                            # print("PATH:", path)
                            npath, params = self.parse_params(npath)
                            if body:
                                params['data'] = body.split("\r\n\r\n")[1]
                            mensaje = f"Path: {npath}\tParametros: {str(params)}"
                            self.logger.log_message(mensaje)
                            response = self.handle_request(method, npath, params)
                            conn.sendall(response)
                    except Exception as e:
                        error_response = self.build_response(500, {
                            "ERROR": "E_SERVER_ERROR", "message": str(e)})
                        conn.sendall(error_response)

    def parse_params(self, npath):
        '''
            If a GET API has params, this function extracts them.
            Imput:
                Path: URI recived.
            Output:
                Path: Resulting path without params.
                Params: List of params received from the GET request.
        '''
        params = {}
        if npath.startswith('/costmap/filter/'):
            params['pid'] = npath.split('/')[3]
            npath = "/costmap/filter"
        elif npath.startswith('/qkd-properties/') or npath.startswith('/endpoints/'):
            params['pid'] = npath.split('/')[2]
            npath = "/"+npath.split('/')[1]
        elif npath.startswith('/all/') or npath.startswith('/best/'):
            params['a'] = npath.split('/')[2]
            params['b'] = npath.split('/')[3]
            npath = "/"+npath.split('/')[1]
        return npath, params

    def handle_request(self, method, npath, params):
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
        if npath in self.routes:
            return self.routes[npath](method, params)
        return self.not_found()

    def not_found(self):
        '''
            404 ERROR handler.
        '''
        return self.build_response(404, {"ERROR": ERRORES["sintax"], "syntax-error": "Not Found"})

    def build_response(self, status_code, data):
        '''
            HTTP response handler.
            Imputs:                Status_code: HTTP Status Code
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
        return self.build_response(400, {"ERROR": ERRORES["sintax"],
                                    "syntax-error": "Method not valid. Required a GET request."})


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
                return self.build_response(400, {"ERROR": ERRORES["valor"],
                                                 "syntax-error": "PID not found."})
            if not isinstance(pid, str):
                return self.build_response(400, {"ERROR": ERRORES["tipo"],
                                "syntax-error": "The PID type is incorrect. We need a string."})
            return self.build_response(200, self.alto.get_costs_map_by_pid(pid))
        return self.build_response(400, {"ERROR": ERRORES["sintax"],
                                "syntax-error": "Method not valid. Required a POST request."})

    # Endpoint Cost Service.
    # To be migrated to a POST method.
    def api_endpoint_costs(self, method, params):
        '''
            Receives an ENDPOINT PID and returns the cost to
            reach to it from the rest of Endpoints.
        '''
        pid = params.get('pid', None)
        if pid is None:
            return self.build_response(400, {"ERROR": ERRORES["valor"],
                                "syntax-error": "PID not found."})
        if not isinstance(pid, str):
            return self.build_response(400, {"ERROR": ERRORES["tipo"],
                                "syntax-error": "The PID type is incorrect. We need a string."})
        return self.build_response(200, self.alto.get_endpoint_costs(pid))

    # Cost Map and Network Map service. Returns both in one request.
    def api_maps(self, method, params):
        """
            Cost Map and Network Map service. Returns both in one request.
            Imput:
                method: GET/POST.
                params: parameters received in the body and/or the URI.
            Output:
                Cost Map and Network Map.
        """
        if method == 'GET':
            return self.build_response(200, self.alto.get_maps())
        if method == 'POST':
            d = params.get('data', None)
            if d is None:
                return self.build_response(400, {"ERROR": ERRORES["valor"],
                                        "syntax-error": "Body not found."})
            data = json.loads(d)
            filtro = data.get('filter', "")
            if filtro == "":
                return self.build_response(400, {"ERROR": ERRORES["campo"],
                                        "syntax-error": "Properties field missing."})
            return self.build_response(200, self.alto.get_maps(filtro))
        return self.build_response(400, {"ERROR": ERRORES["sintax"],
                        "syntax-error": "Method not valid. Required a GET or POST request."})

    # Cost Map service and Filtered Cost Map Service.
    # To be migrated to Filtered API Cost.
    def api_costs(self, method, params):
        """
            Cost Map service and Filtered Cost Map Service. Returns both in one request.
            Imput:
                method: GET/POST.
                params: parameters received in the body and/or the URI.
            Output:
                Cost Map and Filtered Cost Map.
        """
        if method == 'GET':
            return self.build_response(200, self.alto.get_costs_map())
        if method == 'POST':
            d = params.get('data', None)
            if d is None:
                return self.build_response(400, {"ERROR": ERRORES["valor"],
                                        "syntax-error": "Body not found."})
            data = json.loads(d)
            filtro = data.get('filter', "")
            node = data.get('node', "")
            if filtro != "":
                return self.build_response(200, self.alto.get_maps(filtro))
            if node != "":
                return self.build_response(200, self.alto.get_costs_map_by_pid(node))
            return self.build_response(400, {"ERROR": ERRORES["campo"],
                "syntax-error": "Properties field missing. Property fields: node and/or filter"})
        return self.build_response(400, {"ERROR": ERRORES["sintax"],
                        "syntax-error": "Method not valid. Required a GET or POST request."})

    # Network Map Service.
    def api_pids(self, method, params):
        """
            Network Map service. Returns the network map.
            Imput:
                method: GET/POST.
                params: parameters received in the body and/or the URI.
            Output:
                Network Map.
        """
        if method == 'GET':
            return self.build_response(200, self.alto.get_net_map())
        if method == 'POST':
            d = params.get('data', None)
            if d is None:
                return self.build_response(400, {"ERROR": ERRORES["valor"],
                                            "syntax-error": "Body not found."})
            data = json.loads(d)
            filtro = data.get('filter', "")
            return self.build_response(200, self.alto.get_maps(filtro))
        return self.build_response(400, {"ERROR": ERRORES["sintax"],
                        "syntax-error": "Method not valid. Required a GET or POST request."})

    # IRD Service.
    def api_directory(self, method, params):
        """
            IRD Service. Returns the directory of the ALTO server.
            Imput:
                method: GET/POST.
                params: parameters received in the body and/or the URI.
            Output:
                Directory of the ALTO server.
        """
        return self.build_response(200, self.alto.get_directory())

    # Endpoint properties Service.
    def api_properties(self, method, params):
        """
            Endpoint properties Service. Returns the properties of the endpoint.
            Imput:
                method: GET/POST.
                params: parameters received in the body and/or the URI.
            Output:
                Properties of the endpoint.
        """
        pid = params.get('pid', None)
        if pid is None:
            return self.build_response(400, {"ERROR": ERRORES["valor"],
                                    "syntax-error": "PID not found."})
        if not isinstance(pid, str):
            return self.build_response(400, {"ERROR": ERRORES["tipo"],
                        "syntax-error": "The PID type is incorrect. We need a string."})
        if method == 'POST':
            d = params.get('data', None)
            if d is None:
                return self.build_response(400, {"ERROR": ERRORES["valor"],
                                        "syntax-error": "Body not found."})
            data = json.loads(d)
            properties = data.get('properties', [])
            if properties == []:
                return self.build_response(400, {"ERROR": ERRORES["campo"],
                                        "syntax-error": "Properties field missing."})
            pid = data.get('pid', "")
            if pid == "":
                return self.build_response(400, {"ERROR": ERRORES["campo"],
                                        "syntax-error": "PID field missing."})
            if not isinstance(pid, str):
                return self.build_response(400, {"ERROR": ERRORES["tipo"],
                                "syntax-error": "The PID type is incorrect. We need a string."})
            return self.build_response(200, self.alto.get_properties(pid, properties))
        return self.build_response(400, {"ERROR": ERRORES["sintax"],
                                "syntax-error": "Method not valid. Required a POST request."})


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
            if d is None:
                return self.build_response(400, {"ERROR": ERRORES["valor"],
                                            "syntax-error": "Body not found."})
            data = json.loads(d)
            pid = data.get('pid', None)
            link = data.get('link', None)
            if (pid is None) and (link is None) :
                return self.build_response(400, {"ERROR": ERRORES["valor"],
                                "syntax-error": "Node-ID/Link-ID not found. \
                                Please Provide a field node: Node-ID or link:Link-ID."})
            if link is not None:
                if not isinstance(link, str):
                    return self.build_response(400, {"ERROR": ERRORES["tipo"],
                            "syntax-error": "The Link-ID type is incorrect. We need a string."})
                return self.build_response(200, self.alto.get_qkd_link_properties(link))
            if not isinstance(pid, str):
                return self.build_response(400, {"ERROR": ERRORES["tipo"],
                            "syntax-error": "The PID type is incorrect. We need a string."})
            return self.build_response(200, self.alto.get_qkd_properties(pid))
        return self.build_response(400, {"ERROR": ERRORES["sintax"],
                            "syntax-error": "Method not valid. Required a POST request."})


    # Discretion ampliation
    def api_bordernode(self,method, params):
        '''
            API used to identify which nodes in pur network can connect with external net nodes.
            Federation Use Cases.
        '''
        if method == 'POST':
            d = params.get('data', None)
            if d is None:
                return self.build_response(400, {"ERROR": ERRORES["valor"],
                                            "syntax-error": "Body not found."})
            data = json.loads(d)
            mensaje = f"Data:\t {data}"
            self.logger.log_message(mensaje)
            node = data.get('node', "")
            if node != "" :
                #print("NODE:\n", node)
                resp = json.loads(self.alto.get_bordernode(node).replace("'", '"'))
                print("Highlighting link:", resp)

                border_node = resp.get("local")
                remote_node = resp.get("remote")

                # Si existe GUI, remarcar el enlace
                if self.gui:
                    #print("Highlighting link:", border_node, remote_node)
                    self.gui.highlight_link(border_node["qkdn_id"], remote_node["qkdn_id"])

                return self.build_response(200, resp)
                # mens_b = bytes(json.dumps(self.alto.get_bordernode(node)),encoding="utf-8")
                #return self.alto.get_bordernode(node)
                # return self.build_response(200, self.alto.get_bordernode(node))
            return self.build_response(400, {"ERROR": ERRORES["campo"],
                                "syntax-error": "Properties field missing. \
                                    Property fields: node and/or filter"})
        return self.build_response(400, {"ERROR": ERRORES["sintax"],
                        "syntax-error": "Method not valid. Required a POST request."})

    def api_all(self, method, params):
        '''
            Receiving two PIDs returns all disyunts paths that connect them.
        '''
        a = params.get('a', None)
        b = params.get('b', None)
        if a is None or b is None:
            return self.build_response(400, {"ERROR": ERRORES["valor"],
                                    "syntax-error": "Two PIDs are needed."})
        if not isinstance(a, str) or not isinstance(b, str):
            return self.build_response(400, {"ERROR": ERRORES["tipo"],
                                "syntax-error": "The PID type is incorrect. We need two strings."})
        return self.build_response(200, self.alto.parseo_yang(
            str(self.alto.all_maps(a, b)), "all-paths"))

    def api_shortest(self, method, params):
        '''
            Receiving two network Nodes, returns the shortest path between them.
        '''
        a = params.get('a', None)
        b = params.get('b', None)
        if a is None or b is None:
            return self.build_response(400, {"ERROR": ERRORES["valor"],
                                "syntax-error": "Two PIDs are needed."})
        if not isinstance(a, str) or not isinstance(b, str):
            return self.build_response(400, {"ERROR": ERRORES["tipo"],
                                "syntax-error": "The PID type is incorrect. We need two strings."})
        return self.build_response(200, str(self.alto.shortest_path(a, b)))


    ####################################
    ##      Sanitize functions        ##
    ####################################

    def sanitize_input_post(self, texto):
        '''
        Characters acepted in the input: a-zA-Z0-9.{}[]",: -
        '''
        texto_sano = str(texto).replace('#', '').replace('--', '').replace("'", ""
            ).replace("//", "").replace('_', '').replace('<', '').replace('>', ''
            ).replace('&', '').replace('%', '')
        return texto_sano

    def sanitize_input_get(self, texto):
        '''
        Characters acepted in the input: a-zA-Z0-9.:
        '''
        texto_sano = str(texto).replace('#', '').replace('--', '').replace("'", ""
            ).replace("//", "").replace('_', '').replace('<', '').replace('>', ''
            ).replace('&', '').replace('%', '').replace("{", '').replace("}", ""
            ).replace('"', "").replace("-", "")
        return texto_sano

    ####################################
    ##   Federation API functions     ##
    ####################################

    def api_federation(self, method, params):
        '''
            Federation API. It receives a request from a federated server and
            checks if it matches any stored request.
            If it does, it returns the match. If not, it stores the request for future matching.
            Imputs:
                method: POST method. Otherwhise it return a 404 error.
                params: parameters received in the body and/or the URI.
        '''
        if method != 'POST':
            return self.build_response(400, {"ERROR": "E_METHOD",
                                "message": "Only POST allowed."})

        try:
            raw_data = params.get("data", None)
            if not raw_data:
                return self.build_response(400, {"ERROR": "E_NO_BODY",
                                "message": "No body found in request."})

            request = json.loads(raw_data)
            client_address = request.get('remote_ip', None)  # IP del cliente
            if not client_address:
                client_address = 'unknown'

            self.logger.log_message(f"Federation Payload from {client_address}: {request}")

            expiration_time = datetime.datetime.strptime(
                request['expiration_time'], '%Y-%m-%dT%H:%M:%S.%fZ')

            # Verificar si la IP proviene de un servidor federado
            if client_address in [f.split(':', maxsplit=1)[0] for f in self.federados]:
                self.logger.log_message(f"Request from federated server {client_address}")
                # En producción, aquí se haría forward a SDN
                return self.build_response(200, {"status": "forwarded", "code": 0})

            match = self.handle_federated_request(request)
            if match:
                return self.build_response(200, {"status": "Match found",
                                                 "id": match['id'], "code": 1})
            else:
                if self.send_to_federated_servers(request):
                    return self.build_response(200, {"status": "Match found in federated server",
                                                     "id": request['client_app_id'], "code": 1})
                # Si no hay match, guardar la petición
                self.requests.append({
                    'client_app_id': request['client_app_id'][0],
                    'server_app_id': request['server_app_id'],
                    'qos': request['qos'],
                    'id': request['local_qkdn_id'],
                    'expiration_time': expiration_time,
                })
                return self.build_response(200, {"status": "Stored for future matching", "code": 0})

        except Exception as e:
            self.logger.log_message(f"Federation API error: {e}")
            return self.build_response(500, {"ERROR": "E_SERVER_ERROR", "message": str(e)})

    def compare_qos(self, qos1, qos2):
        '''
            Compare two QoS dictionaries.
            Imputs:
                qos1: First QoS dictionary.
                qos2: Second QoS dictionary.
            Output:
                True if both dictionaries are equal.
                False if they are not equal.
        '''
        return all(qos1.get(k) == qos2.get(k) for k in qos1)

    def handle_federated_request(self, request):
        '''
            Handle the federated request and check if it matches any stored request.
            Imputs:
                request: Request to be handled.
            Output:
                Match: If a match is found, return the matched request.
                None: If no match is found.
        '''
        for req in self.requests:
            if (request['client_app_id'][0] == req['client_app_id'] and
                request['server_app_id'] == req['server_app_id'] and
                self.compare_qos(request['qos'], req['qos'])):
                self.requests.remove(req)  # Eliminar la solicitud coincidente
                self.logger.log_message(f"Match found: {req}")
                return req  # Devolver la solicitud coincidente
        return None


    def send_to_federated_servers(self, request):
        '''
            Envia la petición a los servidores federados.
            Imputs:
                request: Petición a enviar.
            Output:
                True si se ha enviado correctamente.
                False si no se ha podido enviar.
        '''
        for federado in self.federados:
            try:
                mensaje = f"Sending to federated: {federado}"
                self.logger.log_message(mensaje)

                endpoint = f"http://{federado}/federation-api"
                enriched_request = request.copy()
                enriched_request["remote_ip"] = self.ip  # Añadimos IP para identificar origen

                response = requests.post(endpoint, timeout=5,
                            json=enriched_request, headers={"Content-Type": "application/json"})
                mess = str(response.text)
                smess = mess.split('\r\n\r\n', maxsplit=1)[-1] if "\r\n\r\n" in mess else mess
                self.logger.log_message(f"Federated server response: {smess}")

                j_res = json.loads(smess)
                if j_res.get("code") == 1:
                    return True
            except Exception as e:
                self.logger.log_message(f"Error connecting to federated server {federado}: {e}")
        return False
