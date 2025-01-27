import datetime

class AltoLogger:
    def __init__(self, file):
        # Obtener la fecha y hora actuales
        now = datetime.datetime.now()
        # Formatear la fecha y hora en el formato deseado
        timestamp = now.strftime("%d%m%Y%H%M")
        # Crear el nombre del archivo de registro
        self.logs = f"{file}_logs{timestamp}.log"

    def log_message(self, message):
        # Obtener el timestamp actual en formato ISO 8601
        current_timestamp = datetime.datetime.now().isoformat()
        # Crear la línea de registro con timestamp y mensaje separados por una tabulación
        log_entry = f"{current_timestamp}\t{message}"
        # Mostrar el mensaje por pantalla
        print(message)
        # Guardar el log en el archivo especificado
        with open(self.logs, 'a') as log_file:
            log_file.write(log_entry + '\n')