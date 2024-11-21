#!/bin/bash

# Manejar CTRL+C para detener tcpdump y salir del script
trap "echo 'Interrumpido con CTRL-C. Finalizando...'; exit" SIGINT

# Activar el entorno virtual
source alto/bin/activate

# Función para verificar si los puertos están libres
check_ports() {
    for port in 8888 5000 9000; do
        if lsof -i:$port >/dev/null; then
            echo "El puerto $port está en uso."
            return 1
        fi
    done
    return 0
}

# Bucle para esperar hasta que los puertos estén disponibles
while true; do
    if check_ports; then
        echo "Todos los puertos están disponibles. Lanzando alto_core.py..."
        break
    else
        echo "Esperando 5 segundos para volver a evaluar..."
        sleep 5
    fi
done

# Iniciar alto_core.py
python3 alto_core.py

# Desactivar el entorno virtual
deactivate

