import socket
import threading
import json

class FederationApi:
    def __init__(self):
        self.requests = []

    def handle_client(self, client_socket):
        if 1:
            # Recibir datos del cliente
            request_data = client_socket.recv(1024).decode('utf-8')
            
            # Parsear los datos recibidos para obtener el cuerpo de la solicitud
            headers, body = request_data.split('\r\n\r\n', 1)
            request_line = headers.splitlines()[0]
            method, path, version = request_line.split()

            if method == 'POST' and path == '/federation-api':
                print(body)
                request = json.loads(body)
                
                # Verificar si hay una coincidencia en las solicitudes
                for req in self.requests:
                    if (request['src'] == req['dst'] and 
                        request['dst'] == req['src'] and 
                        request['qos'] == req['qos']):
                        # Enviar el id de la solicitud coincidente
                        response = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{'message':'Match found', 'id':'{req['id']}'}}\n"
                        client_socket.send(response.encode('utf-8'))
                        
                        # Encontrar el socket correspondiente a la solicitud coincidente
                        matching_socket = req['socket']
                        
                        # Enviar el id de la solicitud actual a la solicitud coincidente
                        response = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{'message':'Match found', 'id':'{request['id']}'}}\n"
                        matching_socket.send(response.encode('utf-8'))
                        
                        # Cerrar ambos sockets
                        matching_socket.close()
                        client_socket.close()
                        
                        # Remover la solicitud coincidente de la lista
                        self.requests.remove(req)
                        
                        return
                
                # Si no hay coincidencia, guardar la solicitud en la lista
                self.requests.append({
                    'src': request['src'],
                    'dst': request['dst'],
                    'qos': request['qos'],
                    'id': request['id'],
                    'socket': client_socket
                })
                response = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{'message':'Peer not found'}}\n"
                matching_socket.send(response.encode('utf-8'))
                        
                
            else:
                response = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nInvalid Request"
                client_socket.send(response.encode('utf-8'))
                client_socket.close()
        #except Exception as e:
        else:
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
