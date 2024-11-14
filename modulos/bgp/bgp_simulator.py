import json
import random
import time
import os
from typing import List, Tuple, Dict

# Constants
MIN_COST = 1
MAX_COST = 100
PROBABILITY_OF_CHANGE = 0.3
UPDATE_INTERVAL_SECONDS = 5
EXABGP_VERSION = "5.0.0"
LOCAL_ASN = 100
ORIGIN = "igp"
LOCAL_PREFERENCE = 100
OSPF_AREA_ID = "0.0.0.1"
STATIC_LOCAL_IP = "60.60.60.2"
STATIC_PEER_IP = "60.60.60.1"

# Global message counter
message_counter = 0

class BGPSimulator:
    def __init__(self, nodes: List[str], links: List[Tuple[str, str, int]]):
        self.nodes = nodes
        self.links = { (link[0], link[1]): link[2] for link in links }
    
    def update_link_costs(self):
        updated_links = []
        for (node1, node2), cost in self.links.items():
            if random.random() < PROBABILITY_OF_CHANGE:
                new_cost = random.randint(MIN_COST, MAX_COST)
                if new_cost != cost:
                    self.links[(node1, node2)] = new_cost
                    updated_links.append(((node1, node2), new_cost))
        return updated_links

    def create_bgp_message(self, links, include_all_links=False):
        global message_counter
        message_counter += 1
        
        # Set message type to "initial_view" if showing all links, otherwise "update"
        message_type = "initial_view" if include_all_links else "update"
        
        bgp_message = {
            "exabgp": EXABGP_VERSION,
            "time": time.time(),
            "host": "router-1",
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "counter": message_counter,
            "type": message_type,
            "neighbor": {
                "address": {
                    "local": STATIC_LOCAL_IP,
                    "peer": STATIC_PEER_IP
                },
                "asn": {
                    "local": LOCAL_ASN,
                    "peer": LOCAL_ASN
                },
                "direction": "send",
                "message": {
                    "update": {
                        "attribute": {
                            "origin": ORIGIN,
                            "local-preference": LOCAL_PREFERENCE,
                            "bgp-ls": {
                                "igp-metric": random.randint(10, 200)
                            },
                            "med": random.randint(1, 500),
                            "originator-id": STATIC_LOCAL_IP,
                            "cluster-list": [STATIC_PEER_IP]
                        },
                        "announce": {
                            "bgp-ls bgp-ls": {}
                        }
                    }
                }
            }
        }
        
        # Populate the announce section with links in the provided list
        for node1, node2, cost in links:
            link_descriptor = {
                "ls-nlri-type": "bgpls-link",
                "l3-routing-topology": 6,
                "protocol-id": 3,
                "local-node-descriptors": [
                    { "autonomous-system": LOCAL_ASN },
                    { "bgp-ls-identifier": "0" },
                    { "ospf-area-id": OSPF_AREA_ID },
                    { "router-id": node1 }
                ],
                "remote-node-descriptors": [
                    { "autonomous-system": LOCAL_ASN },
                    { "bgp-ls-identifier": "0" },
                    { "ospf-area-id": OSPF_AREA_ID },
                    { "router-id": node2 }
                ],
                "interface-addresses": [f"34.34.34.{random.randint(1, 254)}"],
                "neighbor-addresses": [f"34.34.34.{random.randint(1, 254)}"],
                "multi-topology-ids": [],
                "link-identifiers": []
            }
            
            if node1 not in bgp_message["neighbor"]["message"]["update"]["announce"]["bgp-ls bgp-ls"]:
                bgp_message["neighbor"]["message"]["update"]["announce"]["bgp-ls bgp-ls"][node1] = []
            
            bgp_message["neighbor"]["message"]["update"]["announce"]["bgp-ls bgp-ls"][node1].append(link_descriptor)
        
        return bgp_message

    def generate_initial_topology_view(self):
        print("Generating initial topology view...")
        all_links = [(node1, node2, cost) for (node1, node2), cost in self.links.items()]
        bgp_message = self.create_bgp_message(all_links, include_all_links=True)
        # print("Initial Topology Message:", bgp_message)
        return str("decoded UPDATE json ").encode() + str(json.dumps(bgp_message)).encode()
        
    def generate_bgp_updates(self):
        updated_links = self.update_link_costs()
            
        if updated_links:
            links = [(node1, node2, cost) for (node1, node2), cost in updated_links]
            bgp_message = self.create_bgp_message(links, include_all_links=False)
            # print("BGP Update Message:", bgp_message)
            return str("decoded UPDATE json ").encode() + str(json.dumps(bgp_message)).encode()
        else:
            print("BGP Update Message: No changes in topology.")
            return "".encode()


if __name__ =="__main__":
    # Example topology
    nodes = ["10.10.10.1", "10.10.10.2", "10.10.10.3", "10.10.10.4"]
    links = [("10.10.10.1", "10.10.10.2", 10), ("10.10.10.2", "10.10.10.3", 15), ("10.10.10.3", "10.10.10.4", 20), ("10.10.10.4", "10.10.10.1", 25)]

    # Create the topology
    topology = BGPSimulator(nodes, links)

    # Generate the initial view of the topology
    topology.generate_initial_topology_view()

# Start generating BGP updates for a specific duration
# Uncomment the following line to run the periodic updates
# generate_bgp_updates(topology, duration_seconds=60)  # Run for 60 seconds
