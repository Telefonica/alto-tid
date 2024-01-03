#!/usr/bin/env python3

import logging
import pandas as pd
from pybatfish.client.session import Session
from pybatfish.datamodel import *
from pybatfish.datamodel.answer import *
from pybatfish.datamodel.flow import *


# API generada a partir de la información obtenida de: https://pybatfish.readthedocs.io/en/latest/index.html


class BatfishManager:

    def __init__(self, shost='localhost', sname='default', netw='alto'):
        self.session = Session(host=shost)
        self.login = logging.getLogger("pybatfish").setLevel(logging.WARN)
        self.snapshot = {'dir': '/root/cdn-alto/alto-ale/pruebas/', 'name' : str(sname) }
        self.network = str(netw)

        self.session.set_network(self.network)
        self.session.init_snapshot(self.snapshot['dir'], self.snapshot['name'], overwrite=True)
        

    def getSession(self):
        return self.session
