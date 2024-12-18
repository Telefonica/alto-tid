#!/bin/bash 

trap "echo 'Interrumpido con CTRL-C. Finalizando...'; exit" SIGINT

# Activar el entorno virtual
source alto/bin/activate

# Iniciar alto_core.py
python3 alto_core.py

# Desactivar el entorno virtual
deactivate
