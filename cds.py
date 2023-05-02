import base64
import random
import time
import os
import sys
import json
import Attribute
from socket import *
from threading import *
from cryptography.fernet import Fernet

#getting file path
file_path = os.path.dirname(os.path.realpath(__file__))


User_IP = 'localhost'
if len(sys.argv) > 1 and sys.argv[1].isdigit():
    PORT = int(sys.argv[1])
else:
    PORT = 8080


#REPLICATION_FACTOR = 3

#changing the key
def session():

    session_key = Fernet.generate_key()
    encoded_key = base64.urlsafe_b64encode(session_key)
    encoded_key_str = encoded_key.decode('utf-8')

    with open('authentication_key.txt', 'w') as f:
        f.write(encoded_key_str)

session()



server_sock = socket(AF_INET, SOCK_STREAM)
server_sock.bind((User_IP, PORT))
server_sock.listen(5)
print('CDS is running in the system... IP: {0} PORT: {1}'.format(User_IP, PORT))

peer_count = 0

# p_active = {}

# file_system_data = {}

#Encryption
def encrypt_pipeline(json_obj):
    with open('authentication_key.txt', 'r') as f:
        key = f.read()
    decoded_key_str = base64.urlsafe_b64decode(key)
    ferner_ed = Fernet(decoded_key_str)
    cipher = ferner_ed.encrypt(json.dumps(json_obj).encode('ascii'))
    return cipher

#Decryption
def decrypt_pipeline(cipher):
    with open('authentication_key.txt', 'r') as f:
        key = base64.urlsafe_b64decode(f.read())
    ferner_ed = Fernet(key)
    dictionary = json.loads(ferner_ed.decrypt(cipher).decode('ascii'))
    return dictionary




def dummy_data(file_content, path):
    path = os.path.join(file_path, path)
    with open(path, "w") as write_file:
        json.dump(file_content, write_file, indent=4)

#user_credentials = {}

with open(os.path.join(file_path, 'user_credentials.json'), 'r') as file:
    user_credentials = json.loads(file.read())

def nonrepititive_peers(n = Attribute.REPLICATION_FACTOR):
    if n <= len(Attribute.p_active):
        pass  # no need to change n
    else:
        n = len(Attribute.p_active)
    nonrepititive_random_selection_index = random.sample(range(0, len(Attribute.p_active)), n)
    active_peers_ids = list(Attribute.p_active.keys())
    replicated_peers = []

    for index in nonrepititive_random_selection_index:
        replicated_peers.append(active_peers_ids[index])

    return replicated_peers

def process_peer_request(peer_sock, address):
    login_request = decrypt_pipeline(peer_sock.recv(1024))

    while True:
        username = login_request['username']
        password = login_request['password']

        if username in user_credentials and user_credentials[username] == password:
            response = encrypt_pipeline({
                'payload': 'Login successful!'
            })
            peer_sock.send(response)
            break
        else:
            response = encrypt_pipeline({
                'error': 401,
                'payload': 'Username & Password combination doesn\'t exist'
            })
            peer_sock.send(response)
        login_request = decrypt_pipeline(peer_sock.recv(1024))

    global peer_count
    peer_count += 1
    PEER_ID = 'peer_{0}'.format(peer_count)

    peer_details = decrypt_pipeline(peer_sock.recv(1024))
    peer_sock.send(encrypt_pipeline({
        'message': 'Peer {0}, You are now connected to CDS!'.format(peer_count),
        'peer_id': PEER_ID
    }))
    Attribute.p_active[PEER_ID] = {
        'IP': peer_details['IP'],
        'PORT': peer_details['PORT']
    }
    dummy_data(Attribute.p_active, 'p_active.json')
    dummy_data(Attribute.file_system_data, 'file_system_data.json')
    cmd = ''

    while cmd != '<quit>':
        peer_request = decrypt_pipeline(peer_sock.recv(1024))
        cmd = peer_request['cmd']
        if not cmd:
            break
        cmd_parsed = cmd.split()

        if cmd_parsed[0] == 'touch':
            response = {}
            if cmd_parsed[1] in Attribute.file_system_data:
                response = {
                    'error': 400,
                    'payload': '{0} already exists in the system'.format(cmd_parsed[1])
                }
            else:
                permissions = {}
                print(range(2, len(cmd_parsed[2:]) + 2, 2))
                for i in range(2, len(cmd_parsed[2:]) + 2, 2):
                    [peer_id, permission] = [cmd_parsed[i], cmd_parsed[i+1]]
                    permissions[peer_id] = permission
                Attribute.file_system_data[cmd_parsed[1]] = {
                    'owner': PEER_ID,
                    'permissions': permissions,
                    'replicated_peers': nonrepititive_peers(),
                    'encryption_key': str(Fernet.generate_key()),
                    'write_in_progress': 'false',
                    'deleted': 'false',
                    'is_directory': 'false'
                }
                dummy_data(Attribute.file_system_data, 'file_system_data.json')
                for key, values in Attribute.p_active.items():
                    if key != PEER_ID:
                        response[key] = {
                            'IP': values['IP'],
                            'PORT': values['PORT']
                        }
            peer_sock.send(encrypt_pipeline(response))
        elif cmd_parsed[0] == 'mkdir':
            response = {}
            if cmd_parsed[1] in Attribute.file_system_data:
                response = {
                    'error': 400,
                    'payload': '{0} already exists in the system'.format(cmd_parsed[1])
                }
            else:
                print(cmd_parsed)
                Attribute.file_system_data[cmd_parsed[1]] = {
                    'owner': PEER_ID,
                    'permissions': cmd_parsed[2],
                    'replicated_peers': [process for process in Attribute.p_active.keys()],
                    'deleted': 'false',
                    'encryption_key': str(Fernet.generate_key()),
                    'is_directory': 'true'
                }
                dummy_data(Attribute.file_system_data, 'file_system_data.json')
                for key, values in Attribute.p_active.items():
                    if key != PEER_ID:
                        response[key] = {
                            'IP': values['IP'],
                            'PORT': values['PORT']
                        }
            peer_sock.send(encrypt_pipeline(response))
        elif cmd_parsed[0] == 'rmdir':
            response = {}
            if cmd_parsed[1] not in Attribute.file_system_data or Attribute.file_system_data[cmd_parsed[1]]['deleted'] == 'true':
                response = {
                    'error': 404,
                    'payload': 'folder: {0} not found!'.format(cmd_parsed[1])
                }
            else:
                Attribute.file_system_data[cmd_parsed[1]]['deleted'] = 'true'
                dummy_data(Attribute.file_system_data, 'file_system_data.json')
                for key, values in Attribute.p_active.items():
                    if key != PEER_ID:
                        response[key] = {
                            'IP': values['IP'],
                            'PORT': values['PORT']
                        }
            peer_sock.send(encrypt_pipeline(response))
        elif cmd_parsed[0] == 'cat':
            response = {}
            if cmd_parsed[1] not in Attribute.file_system_data:
                response = {
                    'payload': 'file: {0} not found!'.format(cmd_parsed[1]),
                    'error': 404
                }
                peer_sock.send(encrypt_pipeline(response))
                continue
            else:
                # fetch file metadata
                metadata = Attribute.file_system_data[cmd_parsed[1]]
                if PEER_ID in metadata['permissions']:
                    has_access = metadata['permissions'][PEER_ID] == 'w'
                elif PEER_ID == metadata['owner']:
                    has_access = True
                else: 
                    has_access = False
                if Attribute.file_system_data[cmd_parsed[1]]['deleted'] == 'true':
                    response = {
                        'payload': 'file: {0} not found!'.format(cmd_parsed[1]),
                        'error': 404
                    }
                elif metadata['is_directory'] == 'true':
                    response = {
                        'error': 400,
                        'payload': 'file: {0} is a directory'.format(cmd_parsed[1])
                    }
                elif has_access:
                    response['encryption_key'] = metadata['encryption_key']
                    response['replicated_peer_info'] = {}
                    replicated_peers = metadata['replicated_peers']
                    for replicated_peer in replicated_peers:
                        if replicated_peer != PEER_ID:
                            response['replicated_peer_info'][replicated_peer] = Attribute.p_active[replicated_peer]
                    Attribute.file_system_data[cmd_parsed[1]]['write_in_progress'] = 'true'
                else:
                    response = {
                        'payload': '{0} does not have permission to access {1}'.format(PEER_ID, cmd_parsed[1]),
                        'error': 401
                    }
                dummy_data(Attribute.file_system_data, 'file_system_data.json')
                peer_sock.send(encrypt_pipeline(response))
                peer_response = decrypt_pipeline(peer_sock.recv(1024))
                print(peer_response)
                if peer_response['payload'] == 'WRITE_ACK':
                    Attribute.file_system_data[cmd_parsed[1]]['write_in_progress'] = 'false'
                dummy_data(Attribute.file_system_data, 'file_system_data.json')
        elif cmd_parsed[0] == 'read':
            response = {}
            if cmd_parsed[1] not in Attribute.file_system_data:
                response = {
                    'payload': 'file: {0} not found!'.format(cmd_parsed[1]),
                    'error': 404
                }
            else:
                metadata = Attribute.file_system_data[cmd_parsed[1]]
                if 'deleted' in metadata and metadata['deleted'] == 'true':
                    if metadata['owner'] == PEER_ID:
                        response = {
                            'error': 401,
                            'payload': 'file: {0} is deleted\nRun `restore [filename]` to restore the file'.format(cmd_parsed[1])
                        }
                    else:
                        response = {
                            'payload': 'file: {0} not found!'.format(cmd_parsed[1]),
                            'error': 404
                        }
                elif metadata['is_directory'] == 'true':
                    response = {
                        'error': 400,
                        'payload': 'file: {0} is a directory'.format(cmd_parsed[1])
                    }
                elif metadata['write_in_progress'] == 'true':
                    response = {
                        'error': 400,
                        'payload': 'file: {0} is being accessed currently'.format(cmd_parsed[1])
                    }
                else:
                    has_access = False
                    has_access = PEER_ID == metadata['owner'] 
                    if len(metadata['permissions'])!=0 and (metadata['permissions'][PEER_ID] == 'r' or metadata['permissions'][PEER_ID] == 'w'):
                        has_access = True
                    if has_access:
                        response['encryption_key'] = metadata['encryption_key']
                        replicated_peers = metadata['replicated_peers']
                        response['replicated_peer_info'] = {}
                        for replicated_peer in replicated_peers:
                            response['replicated_peer_info'][replicated_peer] = Attribute.p_active[replicated_peer]
                    else:
                        response = {
                            'payload': '{0} does not have permission to access {1}'.format(PEER_ID, cmd_parsed[1]),
                            'error': 401
                        }
            peer_sock.send(encrypt_pipeline(response))
        elif cmd_parsed[0] == 'rm':
            response = {}
            if cmd_parsed[1] not in Attribute.file_system_data:
                response = {
                    'payload': 'file: {0} not found!'.format(cmd_parsed[1]),
                    'error': 404
                }
            else:
                # fetching the file metadata
                metadata = Attribute.file_system_data[cmd_parsed[1]]
                # when the file is access restricted, only the owner can delete
                has_access = PEER_ID == metadata['owner']
                if metadata['write_in_progress'] == 'true':
                    response = {
                        'error': 400,
                        'payload': 'file: {0} is being accessed currently'.format(cmd_parsed[1])
                    }
                elif not has_access:
                    response = {
                        'payload': '{0} does not have permission to delete {1}'.format(PEER_ID, cmd_parsed[1]),
                        'error': 401
                    }
                elif metadata['deleted'] == 'true':
                    response = {
                        'error': 400,
                        'payload': 'file: {0} is deleted already'.format(cmd_parsed[1])
                    }
                else:
                    Attribute.file_system_data[cmd_parsed[1]]['deleted'] = 'true'
                    request = encrypt_pipeline({
                        'cmd': cmd
                    })

                    deleted_in_peers = []
                    for peer in metadata['replicated_peers']:
                        if peer != metadata['owner']:
                            peer_details = Attribute.p_active[peer]
                            peer_IP = peer_details['IP']
                            peer_PORT = peer_details['PORT']
                            print('Connecting to {0}... {1}:{2}'.format(peer, peer_IP, peer_PORT))
                            rep_peer_sock = socket(AF_INET, SOCK_STREAM)
                            rep_peer_sock.connect((peer_IP, int(peer_PORT)))
                            rep_peer_sock.send(request)
                            rep_peer_response = decrypt_pipeline(rep_peer_sock.recv(1024))
                            if 'error' in rep_peer_response:
                                print(rep_peer_response['payload'])
                            else:
                                deleted_in_peers.append(peer)
                                print(rep_peer_response['payload'])
                            print()
                    response = {
                        'payload': '{0} deleted successfully accross {1}.'.format(cmd_parsed[1], deleted_in_peers)
                    }
                    for peer in deleted_in_peers:
                        Attribute.file_system_data[cmd_parsed[1]]['replicated_peers'].remove(peer)
                    dummy_data(Attribute.file_system_data, 'file_system_data.json')
            print(response)
            peer_sock.send(encrypt_pipeline(response))
        elif cmd_parsed[0] == 'restore':
            response = {}
            if cmd_parsed[1] not in Attribute.file_system_data:
                response = {
                    'payload': 'file: {0} not found!'.format(cmd_parsed[1]),
                    'error': 404
                }
            else:
                metadata = Attribute.file_system_data[cmd_parsed[1]]
                if 'deleted' in metadata and metadata['deleted'] != "true":
                    response = {
                        'payload': 'file: {0} does not exists in the bin'.format(cmd_parsed[1]),
                        'error': 400
                    }
                elif metadata['owner'] != PEER_ID:
                    response = {
                        'payload': 'file: {0} can be restored only by the owner'.format(cmd_parsed[1]),
                        'error': 403
                    }
                else:
                    response['peers_to_replicate'] = []
                    for peer in nonrepititive_peers():
                        Attribute.file_system_data[cmd_parsed[1]]['replicated_peers'].append(peer)
                        response['peers_to_replicate'].append({
                            "IP": Attribute.p_active[peer]["IP"],
                            "PORT": Attribute.p_active[peer]["PORT"]
                        })
                    response['payload'] = 'SIG_REPLICATE'
                Attribute.file_system_data[cmd_parsed[1]]['deleted'] = 'false'
                peer_sock.send(encrypt_pipeline(response))
                dummy_data(Attribute.file_system_data, 'file_system_data.json')
        elif cmd_parsed[0] == 'ls':
            response = {
                'payload': []
            }
            for key, value in Attribute.file_system_data.items():
                line = ''

                # if file is restricted, or deleted and owner is not the current peer, do not show the file
                if (value['permissions'] == "3" or value['deleted'] == 'true') and value['owner'] != PEER_ID:
                    continue

                file_name = key

                line += 'd' if value['is_directory'] == 'true' else '-'
                line += ' '

                if value['permissions'] == '1':
                    line += 'r/w'
                elif value['permissions'] == '2':
                    line += 'r/w' if value['owner'] == PEER_ID else 'r'
                else:
                    line += 'r*'
                line += ' '

                line += file_name
                response['payload'].append(line)
            print(response)
            peer_sock.send(encrypt_pipeline(response))
    print(PEER_ID, 'is disconnected!')
    # removing the peer info
    Attribute.p_active.pop(PEER_ID, None)
    dummy_data(Attribute.p_active, 'p_active.json')

#checking malicious activity
def malicious_activity_checker():
    request = {
        'cmd': 'FILE_LISTING_RQST'
    }
    while True:
        time.sleep(150)
        for peer, value in Attribute.p_active.items():
            print('Checking for malicious activity in {0}'.format(peer))
            peer_IP = value['IP']
            peer_PORT = value['PORT']
            peer_sock = socket(AF_INET, SOCK_STREAM)
            peer_sock.connect((peer_IP, int(peer_PORT)))
            peer_sock.send(encrypt_pipeline(request))
            peer_response = decrypt_pipeline(peer_sock.recv(1024))
            print(peer_response)
            red_flag = False

            # checking the maliciously deleted files
            for key, value in Attribute.file_system_data.items():
                if red_flag:
                    break
                if 'deleted' not in value or ('deleted' in value and value['deleted'] != 'true'):
                    if key not in peer_response['file_list']:
                        red_flag = True

                elif value['owner'] != peer_response['peer_id']:
                    red_flag = True

            # checking the maliciously added files
            for file in peer_response['file_list']:
                if red_flag:
                    break
                if file not in Attribute.file_system_data:
                    red_flag = True

            if red_flag:
                print('{0} has been compromised'.format(peer_response['peer_id']))
        print()

def create_peer():
    while True:
        inp = input()
        inp_parsed = inp.split()

        if len(inp_parsed) == 2:
            [username, password] = inp_parsed
            user_credentials[username] = password
            print('Peer registered')

def main():
    peer_registration_thread = Thread(target = create_peer)
    peer_registration_thread.start()

    while True:
        peer_sock, address = server_sock.accept()
        peer_request_processor_thread = Thread(target = process_peer_request, args=(peer_sock, address))
        peer_request_processor_thread.setDaemon(True)
        peer_request_processor_thread.start()

if __name__ == '__main__':
    main()

server_sock.close()