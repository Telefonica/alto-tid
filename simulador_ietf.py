#!/usr/bin/env python3
#© 2024 Telefónica Innovación Digital, All rights reserved


import os
import re
import random
from time import sleep

#Definimos variables
n_cambios = 3
topo = ""
values = [10, 20, 30, 40, -1]
comodin = '"metric1": "'

def skere():
    # leemos el archivo de ietf
    try:
        in_file = open('/root/ietf_prueba.json','r')
    except Exception as e:
        print(e)
        return
    else:
        topo = in_file.read()
    finally:
        in_file.close()

    # bucle: creamos 3 numeros aleatorios pra seleccionar cambios y 3 valores en una lista para aplicarlos
    while 1:
        sleep(15)
        l_aux = [m.start() for m in re.finditer(r'"metric1": "', topo)]
        r_list = [random.randint(0, len(l_aux)) for i in range(3)]
        for rn in r_list:
            #Aquí buscamos la rn ocurrencia de metric1 en el string
            #Generamos un valor aleatorio del 0 al 4 y seleccionamos el respectivo values
            #Sustituímos según patrones (revisar cómo aplicar regex en python)
            rval = random.randint(0,4)
            topo = topo[:l_aux[rn]+12] + str(values[rval]) + topo[l_aux[rn]+14:]
            print(str(rn))

        #Sobrescribimos sobre ietf2
        with open('/root/ietf2_prueba.json', 'w') as out_file:
            err = out_file.write(topo)
            out_file.close()



skere()
