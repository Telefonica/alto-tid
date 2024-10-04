import datetime
import socket
import threading
import json

class FederationApi:
    def __init__(self):
        self.requests = []
        self.federados = ["192.168.159.74:9999"]        

    # Función para comparar QoS
    def compare_qos(self, qos1, qos2):
        return all(qos1.get(k) == qos2.get(k) for k in qos1)

    # Función para manejar peticiones federadas
    def handle_federated_request(self, request):
        # self.clean_expired_requests()  # Eliminar peticiones expiradas antes de buscar coincidencias
        for req in self.requests:
            if (request['client_app_id'][0] == req['client_app_id'] and 
                request['server_app_id'] == req['server_app_id'] and 
                self.compare_qos(request['qos'], req['qos']) ): # and
                #datetime.datetime.now(datetime.timezone.utc) < req['expiration_time']):
                self.requests.remove(req)  # Eliminar la solicitud coincidente localmente                
                return req  # Devolver la solicitud coincidente si hay match
            #print(request['client_app_id'][0] , req['client_app_id'] ,request['server_app_id'] , req['server_app_id'] , self.compare_qos(request['qos'], req['qos']))
        return None

    # Función para enviar petición a servidores federados
    def send_to_federated_servers(self, request):
        if isinstance(request, str):
            request = json.loads(request)
        if 'federated_hop_count' not in request:
            request['federated_hop_count'] = 0  # Inicializar si no existe
        request['federated_hop_count'] += 1
        
        # No reenviar la solicitud si ya pasó por más de un número razonable de servidores
        if request['federated_hop_count'] > len(self.federados):
            print("Max federated hop count reached, avoiding loop.")
            return False
        for federado in self.federados:
            print("FEDERADO:\t", federado)
            ip, port = federado.split(':')
            try:
                depured_r = str(request).replace("True", '"True"').replace("False",'"False"').replace("true", '"true"').replace("false",'"false"')
                json_data = json.dumps(depured_r)
                federated_socket = socket.create_connection((ip, int(port)))
                federated_request  = "POST /federation-api HTTP/1.1\r\n"
                federated_request += f"Host: ({ip}:{port})\r\n"
                federated_request += "Content-Type: application/json\r\n"
                federated_request += f"Content-Length: {len(json_data)}\r\n"
                federated_request += "Connection: close\r\n\r\n"
                federated_request += json_data

                #federated_request = f"POST /federation-api HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{json.dumps(request)}"
                print("Fed-request\t",federated_request)
                federated_socket.sendall(federated_request.encode('utf-8'))

                response = federated_socket.recv(1024).decode('utf-8')
                try:
                    headers, body = response.split('\r\n\r\n', 1)
                    response_data = json.loads(body)
                except ValueError:
                    print("Peer Not Found: Response does not contain headers and body separated by '\\r\\n\\r\\n'")
                    response_data = {}

                if response_data.get('message') == 'Match found':
                    return True  # Si se encontró coincidencia en otro servidor
            except Exception as e:
                print(f"Error connecting to federado {federado}: {e}")
        return False

    # Eliminar solicitudes expiradas
    def clean_expired_requests(self):
        current_time = datetime.datetime.now(datetime.timezone.utc)
        self.requests = [req for req in self.requests if req['expiration_time'] > current_time]

    def handle_client(self, client_socket):
        try:
        #if 1:
            # Recibir datos del cliente
            request_data = client_socket.recv(1024).decode('utf-8')
            
            # Parsear los datos recibidos para obtener el cuerpo de la solicitud
            headers, body = request_data.split('\r\n\r\n', 1)
            request_line = headers.splitlines()[0]
            method, path, version = request_line.split()

            if method == 'POST' and path == '/federation-api':
                request = json.loads(body)
                
                # Parsear el campo expiration_time a un objeto datetime
                expiration_time = datetime.datetime.strptime(request['expiration_time'], '%Y-%m-%dT%H:%M:%S.%fZ')
                
                # Verificar si hay una coincidencia en las solicitudes
                # Verificar si hay una coincidencia en las solicitudes locales
                match = self.handle_federated_request(request)
                if match:
                    #print(match)
                    # Enviar el id de la solicitud coincidente
                    response = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{'message':'Match found', 'id':'{match['id']}'}}\n"
                    client_socket.send(response.encode('utf-8'))

                    # Enviar el id de la solicitud actual a la solicitud coincidente
                    matching_socket = match['socket']
                    response = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{'message':'Match found', 'id':'{request['local_qkdn_id']}'}}\n"
                    matching_socket.send(response.encode('utf-8'))

                    # Cerrar ambos sockets
                    matching_socket.close()
                    client_socket.close()

                    # Remover la solicitud coincidente de la lista
                    # self.requests.remove(match)
                    return
                else:
                    print("NO MATCH")
                    # Si no hay coincidencia local, buscar en servidores federados
                    if self.send_to_federated_servers(request):
                        response = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{'message':'Match found in federated server'}}\n"
                        client_socket.send(response.encode('utf-8'))
                        client_socket.close()
                        return
                    # Si no se encontró coincidencia en servidores federados, guardar la solicitud localmente
                    self.requests.append({
                        'client_app_id': request['client_app_id'][0],
                        'server_app_id': request['server_app_id'],
                        'qos': request['qos'],
                        'id': request['local_qkdn_id'],
                        'socket': client_socket,
                        'expiration_time': expiration_time
                    })
                    response = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{'message':'Peer not found'}}\n"
                    client_socket.send(response.encode('utf-8'))
            else:
                response = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nInvalid Request"
                client_socket.send(response.encode('utf-8'))
                client_socket.close()
        except Exception as e:
            print(f"Error handling client: {e}")
            client_socket.close()

    def server_loop(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('0.0.0.0', 9999))
        server.listen(5)
        print("Server listening on port 9999")

        while True:
            client_socket, addr = server.accept()
            print(f"Accepted connection from {addr}")
            client_handler = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_handler.start()

if __name__ == '__main__':
    api = FederationApi()
    api.server_loop()
