import datetime
import socket
import threading
import json
import requests

class FederationApi:
    def __init__(self):
        self.requests = []
        self.federados = ["192.168.159.83:9999"]
        self.sdn = "192.168.159.236:80"

    # Función para comparar QoS
    def compare_qos(self, qos1, qos2):
        return all(qos1.get(k) == qos2.get(k) for k in qos1)

    # Función para manejar peticiones federadas
    def handle_federated_request(self, request):
        # self.clean_expired_requests()  # Eliminar peticiones expiradas antes de buscar coincidencias
        print("COMPARATIVA:\n", request)
        for req in self.requests:
            if (request['client_app_id'][0] == req['client_app_id'] and
                request['server_app_id'] == req['server_app_id'] and
                self.compare_qos(request['qos'], req['qos']) ): # and
                #datetime.datetime.now(datetime.timezone.utc) < req['expiration_time']):
                self.requests.remove(req)  # Eliminar la solicitud coincidente localmente
                return req  # Devolver la solicitud coincidente si hay match
            #print(request['client_app_id'][0] , req['client_app_id'] ,request['server_app_id'] , req['server_app_id'] , self.compare_qos(request['qos'], req['qos']))
        return None

    # Función para manejar peticiones federadas desde servidores federados
    def forward_to_sdn(self, request, federated_socket):
        try:
            try:
                j_request = json.loads(request.replace("'", '"'))
            except:
                j_request = request
            print("PAYLOAD SEND:\n", j_request)
            endpoint = "http://" + self.sdn + "/webui/qkd/appRegistry/registerQkdApp"
            response = requests.post(endpoint, json=j_request, headers={"Content-Type": "application/json"})
            print(f"SDN Response: {response.status_code}, {response.text}")

            # Checking the local status.
            resp = self.handle_federated_request(j_request)
            if resp:
                federated_response = {"code": 1, " status": "Match found", "id": [resp['client_app_id']]}
                f_response = ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + json.dumps(federated_response) + '\n').encode('utf-8')
                resp["socket"].sendall(f_response)
            else:
                federated_response = {"code": 0, " status": "Match not found"}
                
            # f_response = json.dumps(federated_response).encode('utf-8')
            print("Federated response:\n", federated_response)
            f_response = ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + json.dumps(federated_response) + '\n').encode('utf-8')
            federated_socket.send(f_response)
            #federated_socket.send(json.dumps(federated_response).encode('utf-8'))

        except requests.RequestException as e:
            print(f"Error forwarding to SDN: {e}")
            error_response = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nError forwarding to SDN"
            federated_socket.send(error_response.encode('utf-8'))



    # Fuinción para enviar petición a servidores federados
    def send_to_federated_servers(self, request):
        for federado in self.federados:
            print("FEDERADO:\t", federado)
            #ip, port = federado.split(':')
            try:
                try:
                    j_request = json.loads(request.replace("'", '"'))
                except:
                    j_request = request
                #j_request["expiration_time"] = "2024-10-12T12:30:50.55Z"
                print("PAYLOAD SEND:\n", j_request)
                endpoint = "http://" + self.federados[0] + "/federation-api"
                response = requests.post(endpoint, json=j_request, headers={"Content-Type": "application/json"})
                mess = str(response.text)
                smess = mess.split("\r\n\r\n")[-1]
                print("RESPONSE:\t", mess)
                j_res = json.loads(smess)
                #j_res = json.loads(response.message)
                #j_res = response.json()
                if j_res["code"]:
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
            request_data = client_socket.recv(2048).decode('utf-8')

            # Parsear los datos recibidos para obtener el cuerpo de la solicitud
            headers, body = request_data.split('\r\n\r\n', 1)
            request_line = headers.splitlines()[0]
            method, path, version = request_line.split()

            if method == 'POST' and path == '/federation-api':
                request = json.loads(body)
                print("PAYLOAD:\n", body)

                # Comprobar si la petición proviene de un servidor federado
                client_address = client_socket.getpeername()[0]
                if client_address in [f.split(':')[0] for f in self.federados]:
                    print(f"Request received from federated server: {client_address}")
                    # Reenviar al servidor SDN
                    self.forward_to_sdn(request, client_socket)
                    client_socket.close()
                    return


                # Parsear el campo expiration_time a un objeto datetime
                expiration_time = datetime.datetime.strptime(request['expiration_time'], '%Y-%m-%dT%H:%M:%S.%fZ')

                # Verificar si hay una coincidencia en las solicitudes
                # Verificar si hay una coincidencia en las solicitudes locales
                match = self.handle_federated_request(request)
                if match:
                    #print(match)
                    # Enviar el id de la solicitud coincidente
                    response = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{'message':'Match found', 'id':'{match['id']}'}}"
                    print("RESPUESTA ENVIADA:\n", response)
                    client_socket.sendall(response.encode('utf-8'))

                    # Enviar el id de la solicitud actual a la solicitud coincidente
                    matching_socket = match['socket']
                    response = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{'message':'Match found', 'id':'{request['local_qkdn_id']}'}}"
                    print("RESPUESTA ENVIADA:\n", response)
                    matching_socket.sendall(response.encode('utf-8'))

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
                        federated_response = {"code": 1, " status": "Match found", "id": request['client_app_id']}
                        f_response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + json.dumps(federated_response) + '\n'
                        #response = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{'message':'Match found in federated server'}}\n"
                        print("RESPUESTA ENVIADA:\n", f_response)
                        client_socket.sendall(f_response.encode('utf-8'))
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
                    response = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{'message':'Peer not found'}}\n"
                    print("RESPUESTA ENVIADA:\n", response)
                    client_socket.sendall(response.encode('utf-8'))
                    client_socket.close()
                    return
                    #client_socket.shutdown(socket.SHUT_WR)
            else:
                response = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nHTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\Innvalid Request"
                print("MENSAJE RECIBIDO:\n", body)
                print("RESPUESTA ENVIADA:\n", response)
                client_socket.sendall(response.encode('utf-8'))
                #client_socket.shutdown(socket.SHUT_WR)
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
