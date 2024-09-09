import socket
import threading
import json
import time
import logging
import os
import requests

# Crear el directorio 'log' si no existe
if not os.path.exists('log'):
    os.makedirs('log')

# Configurar el registro de errores
logging.basicConfig(
    filename='log/federation_api.log',
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class FederationApi:
    def __init__(self, node_config):
        # Cola persistente para almacenar las solicitudes con un timestamp
        self.requests = []
        self.lock = threading.Lock()

        # Lista de nodos vecinos (otros servidores)
        self.neighbor_nodes = node_config['neighbors']

        # Iniciar un hilo para limpiar solicitudes expiradas
        cleaner_thread = threading.Thread(target=self.clean_expired_requests)
        cleaner_thread.daemon = True
        cleaner_thread.start()

    def handle_client(self, client_socket):
        try:
            # Recibir datos del cliente
            request_data = client_socket.recv(1024).decode('utf-8')

            # Parsear los datos recibidos para obtener el cuerpo de la solicitud
            headers, body = request_data.split('\r\n\r\n', 1)
            request_line = headers.splitlines()[0]
            method, path, version = request_line.split()

            if method == 'POST' and path == '/federation-api':
                print(body)
                request = json.loads(body)

                # Verificar si hay una coincidencia en las solicitudes locales
                match_found = False
                with self.lock:
                    for req in self.requests:
                        if (request['src'] == req['dst'] and
                            request['dst'] == req['src'] and
                            request['qos'] == req['qos']):
                            
                            # Notificar ambas partes de la coincidencia
                            response = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{'message':'Match found', 'id':'{req['id']}'}}\n"
                            client_socket.send(response.encode('utf-8'))

                            matching_socket = req['socket']
                            response = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{'message':'Match found', 'id':'{request['id']}'}}\n"
                            matching_socket.send(response.encode('utf-8'))

                            # Cerrar ambos sockets
                            matching_socket.close()
                            client_socket.close()

                            # Remover ambas solicitudes de la lista
                            self.requests.remove(req)
                            match_found = True
                            break

                # Si no hay coincidencia, intentar en nodos vecinos
                if not match_found:
                    response = self.check_neighbors_for_match(request)
                    
                    if response and response['match_found']:
                        # Notificar a este cliente de la coincidencia encontrada en un nodo vecino
                        response_message = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{'message':'Match found in neighbor', 'id':'{response['match_id']}'}}\n"
                        client_socket.send(response_message.encode('utf-8'))
                        client_socket.close()
                    else:
                        # No hay coincidencia, agregar a la cola local con timestamp
                        with self.lock:
                            self.requests.append({
                                'src': request['src'],
                                'dst': request['dst'],
                                'qos': request['qos'],
                                'id': request['id'],
                                'socket': client_socket,
                                'timestamp': time.time()  # Guardar tiempo de llegada
                            })
                        response_message = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{'message':'Peer not found, waiting for match'}}\n"
                        client_socket.send(response_message.encode('utf-8'))

            else:
                response = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nInvalid Request"
                client_socket.send(response.encode('utf-8'))
                client_socket.close()

        except Exception as e:
            logging.error(f"Error handling client: {e}")
            client_socket.close()

    def check_neighbors_for_match(self, request):
        # Enviar la solicitud a los nodos vecinos y ver si alguno tiene coincidencia
        for node in self.neighbor_nodes:
            try:
                neighbor_url = f"http://{node['host']}:{node['port']}/federation-api/check-match"
                response = requests.post(neighbor_url, json=request)
                
                if response.status_code == 200:
                    data = response.json()
                    if data['match_found']:
                        return data  # Devolver la respuesta del nodo vecino
            except Exception as e:
                logging.error(f"Error contacting neighbor {node['host']}:{node['port']} - {e}")

        return None

    def clean_expired_requests(self):
        while True:
            current_time = time.time()
            with self.lock:
                # Remover solicitudes que lleven más de 30 segundos en la cola
                self.requests = [req for req in self.requests if current_time - req['timestamp'] < 30]

            time.sleep(1)  # Verificar cada segundo

    def check_match_endpoint(self, request):
        # Endpoint interno para que los nodos remotos verifiquen coincidencias en este nodo
        match_found = False
        with self.lock:
            for req in self.requests:
                if (request['src'] == req['dst'] and
                    request['dst'] == req['src'] and
                    request['qos'] == req['qos']):
                    
                    # Encontrar coincidencia y removerla de la lista
                    self.requests.remove(req)
                    match_found = True
                    return {
                        'match_found': True,
                        'match_id': req['id']
                    }

        return {
            'match_found': False
        }

    def server_loop(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('0.0.0.0', 9999))
        server.listen(5)
        print("Server listening on port 9999")

        while True:
            try:
                client_socket, addr = server.accept()
                print(f"Accepted connection from {addr}")
                client_handler = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_handler.start()
            except Exception as e:
                logging.error(f"Error accepting connection: {e}")

if __name__ == '__main__':
    # Configuración de nodos vecinos
    node_config = {
        'neighbors': [
            {'host': '192.168.159.74', 'port': 9999}
        ]
    }

    api = FederationApi(node_config)
    api.server_loop()

