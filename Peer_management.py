# Peer_management
import Attribute
import json
import os
import random


with open(os.path.join(Attribute.curr_file_path, 'user_credentials.json'), 'r') as file:
    user_credentials = json.loads(file.read())
def nonrepititive_peers(n = Attribute.REPLICATION_FACTOR):
    if n <= len(Attribute.p_active):
        pass
    else:
        n = len(Attribute.p_active)
    nonrepititive_random_selection_index = random.sample(range(0, len(Attribute.p_active)), n)
    active_peers_ids = list(Attribute.p_active.keys())
    replicated_peers = []

    for index in nonrepititive_random_selection_index:
        replicated_peers.append(active_peers_ids[index])

    return replicated_peers

def create_peer():
    while True:
        inp = input().split()
        
        if len(inp) == 2:
            username, password = inp
            user_credentials.update({username: password})
            print('Peer registered')