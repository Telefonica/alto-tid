#!/usr/bin/env python3

import sys
import threading
sys.path.append('cdn-alto/')
sys.path.append('alto-ale/')
from topology_maps_generator import TopologyCreator
from desuso.exponsure import ApiHttp


#Creation of ALTO modules
modules={}
modules['bgp'] = TopologyBGP(('localhost',8080))
#modules['ietf'] = TopologyIetf(('localhost',8081))
alto = TopologyCreator(modules, 0)
threads = list()
for modulo in modules.keys():
    print(modulo)
    x = threading.Thread(target=alto.gestiona_info, args=(modulo,))#, daemon=True)
    threads.append(x)
    x.start()

a = threading.Thread(target=alto.mailbox)
threads.append(a)
a.start()
app.run()

