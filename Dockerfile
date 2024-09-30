# Usa una imagen base de Python (o la que necesites)
FROM python:3.10-alpine

# Establece el directorio de trabajo
WORKDIR /app

COPY requirements.txt /app/

# Instalar dependencias del sistema
#RUN apt-get update && apt-get install -y build-essential libyaml-dev

# Actualizar pip, setuptools y wheel
#RUN pip3 install --upgrade pip setuptools wheel
# Instalar Cython
#RUN pip3 install cython
# Instalar PyYAML desde una rueda precompilada
#RUN pip3 install PyYAML==5.4.1 --no-binary :all:

# Instalar dependencias de Python
RUN pip3 install -r requirements.txt

COPY . /app

# Expone los puertos necesarios
EXPOSE 8080 9999

# Comando para ejecutar la aplicación
CMD ["python3", "api/web/federation.py", "&"]
CMD ["python3", "alto_core.py"]

