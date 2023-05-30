#!/usr/bin/env python3

import os
import json


class TopologyFileWriter:

    def __init__(self, output_path="./maps"):
        self.output_path = output_path
        self.pid_file = 'pid_file.json'
        self.cost_map_file = 'cost_map.json'
        self.same_node_ips = "router_ids.json"

    def write_file(self, file_name, content_to_write):
        """Writes file_name in output_file"""
        full_path = os.path.join(self.output_path, file_name)
        with open(full_path, 'w') as out_file:
            json.dump(content_to_write, out_file, indent=4)

    def write_pid_file(self, content):
        self.write_file(self.pid_file, content)

    def write_cost_map(self, content):
        self.write_file(self.cost_map_file, content)

    def write_same_ips(self, content):
        self.write_file(self.same_node_ips, content)


