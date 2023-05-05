import base64
import time
import sys
import Peer_management
import Attribute
import Malicious_activity_watcher
from socket import *
from threading import *
from cryptography.fernet import Fernet


if len(sys.argv) > 1 and sys.argv[1].isdigit():
    PORT = int(sys.argv[1])
else:
    PORT = 8080


#changing the key
def session():

    session_key = Fernet.generate_key()
    encoded_key = base64.urlsafe_b64encode(session_key)
    encoded_key_str = encoded_key.decode('utf-8')

    with open('authentication_key.txt', 'w') as file:
        file.write(encoded_key_str)

session()


#server socket connection
server_sock = socket(AF_INET, SOCK_STREAM)
server_sock.bind((Attribute.User_IP, PORT))
server_sock.listen(5)
print('CDS is running in the system... IP: {0} PORT: {1}'.format(Attribute.User_IP, PORT))

peer_count = 0


def process_peer_request(peer_sock, address):
    login_request = Attribute.decrypt_pipeline(peer_sock.recv(1024))

    while True:
        username = login_request['username']
        password = login_request['password']

        if username in Peer_management.user_credentials and Peer_management.user_credentials[username] == password:
            response = Attribute.encrypt_pipeline({
                'payload': 'Login successful!'
            })
            peer_sock.send(response)
            break
        else:
            response = Attribute.encrypt_pipeline({
                'error': 401,
                'payload': 'Username & Password combination doesn\'t exist'
            })
            peer_sock.send(response)
        login_request = Attribute.decrypt_pipeline(peer_sock.recv(1024))

    global peer_count
    peer_count += 1
    PEER_ID = 'peer_{0}'.format(peer_count)

    peer_details = Attribute.decrypt_pipeline(peer_sock.recv(1024))
    peer_sock.send(Attribute.encrypt_pipeline({
        'message': 'Peer {0}, You are now connected to CDS!'.format(peer_count),
        'peer_id': PEER_ID
    }))
    Attribute.p_active[PEER_ID] = {
        'IP': peer_details['IP'],
        'PORT': peer_details['PORT']
    }
    Attribute.user_dummy_data(Attribute.p_active, 'p_active.json')
    Attribute.user_dummy_data(Attribute.file_details, 'file_details.json')
    cmd = ''

    while cmd != '<quit>':
        peer_request = Attribute.decrypt_pipeline(peer_sock.recv(1024))
        cmd = peer_request['cmd']
        if not cmd:
            break
        cmd_parsed = cmd.split()

        if cmd_parsed[0] == 'touch':
            response = {}
            if cmd_parsed[1] in Attribute.file_details:
                response = {
                    'error': 400,
                    'payload': '{0} already exists in the system'.format(cmd_parsed[1])
                }
            else:
                permissions = {}
                for i in range(2, len(cmd_parsed[2:]) + 2, 2):
                    [peer_id, permission] = [cmd_parsed[i], cmd_parsed[i+1]]
                    permissions[peer_id] = permission
                Attribute.file_details[cmd_parsed[1]] = {
                    'owner': PEER_ID,
                    'permissions': permissions,
                    'replicated_peers': Peer_management.nonrepititive_peers(),
                    'encryption_key': str(Fernet.generate_key()),
                    'write_in_progress': 'false',
                    'deleted': 'false',
                    'is_directory': 'false'
                }
                Attribute.user_dummy_data(Attribute.file_details, 'file_details.json')
                for key, values in Attribute.p_active.items():
                    if key != PEER_ID:
                        response[key] = {
                            'IP': values['IP'],
                            'PORT': values['PORT']
                        }
            peer_sock.send(Attribute.encrypt_pipeline(response))
        elif cmd_parsed[0] == 'mkdir':
            response = {}
            if cmd_parsed[1] in Attribute.file_details:
                response = {
                    'error': 400,
                    'payload': '{0} already exists in the system'.format(cmd_parsed[1])
                }
            else:
                print(cmd_parsed)
                Attribute.file_details[cmd_parsed[1]] = {
                    'owner': PEER_ID,
                    'permissions': cmd_parsed[2],
                    'replicated_peers': [process for process in Attribute.p_active.keys()],
                    'deleted': 'false',
                    'encryption_key': str(Fernet.generate_key()),
                    'is_directory': 'true'
                }
                Attribute.user_dummy_data(Attribute.file_details, 'file_details.json')
                for key, values in Attribute.p_active.items():
                    if key != PEER_ID:
                        response[key] = {
                            'IP': values['IP'],
                            'PORT': values['PORT']
                        }
            peer_sock.send(Attribute.encrypt_pipeline(response))
        elif cmd_parsed[0] == 'rmdir':
            response = {}
            if cmd_parsed[1] not in Attribute.file_details or Attribute.file_details[cmd_parsed[1]]['deleted'] == 'true':
                response = {
                    'error': 404,
                    'payload': 'folder: {0} not found!'.format(cmd_parsed[1])
                }
            else:
                Attribute.file_details[cmd_parsed[1]]['deleted'] = 'true'
                Attribute.user_dummy_data(Attribute.file_details, 'file_details.json')
                for key, values in Attribute.p_active.items():
                    if key != PEER_ID:
                        response[key] = {
                            'IP': values['IP'],
                            'PORT': values['PORT']
                        }
            peer_sock.send(Attribute.encrypt_pipeline(response))
        elif cmd_parsed[0] == 'cat':
            response = {}
            if cmd_parsed[1] not in Attribute.file_details:
                response = {
                    'payload': 'file: {0} not found!'.format(cmd_parsed[1]),
                    'error': 404
                }
                peer_sock.send(Attribute.encrypt_pipeline(response))
                continue
            else:
                # fetch file of metadata for writing
                metadata = Attribute.file_details[cmd_parsed[1]]
                if PEER_ID in metadata['permissions']:
                    has_access = metadata['permissions'][PEER_ID] == 'w'
                elif PEER_ID == metadata['owner']:
                    has_access = True
                else: 
                    has_access = False
                if Attribute.file_details[cmd_parsed[1]]['deleted'] == 'true':
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
                    Attribute.file_details[cmd_parsed[1]]['write_in_progress'] = 'true'
                else:
                    response = {
                        'payload': '{0} does not have permission to access {1}'.format(PEER_ID, cmd_parsed[1]),
                        'error': 401
                    }
                Attribute.user_dummy_data(Attribute.file_details, 'file_details.json')
                peer_sock.send(Attribute.encrypt_pipeline(response))
                peer_response = Attribute.decrypt_pipeline(peer_sock.recv(1024))
                print(peer_response)
                if peer_response['payload'] == 'WRITE_ACK':
                    Attribute.file_details[cmd_parsed[1]]['write_in_progress'] = 'false'
                Attribute.user_dummy_data(Attribute.file_details, 'file_details.json')
        elif cmd_parsed[0] == 'read':
            response = {}
            if cmd_parsed[1] not in Attribute.file_details:
                response = {
                    'payload': 'file: {0} not found!'.format(cmd_parsed[1]),
                    'error': 404
                }
            else:
                metadata = Attribute.file_details[cmd_parsed[1]]
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
                    if len(metadata['permissions'])!=0:
                        has_access = True
                    if PEER_ID in metadata['permissions'] and  (metadata['permissions'][PEER_ID] == 'r' or metadata['permissions'][PEER_ID] == 'w'):
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
            peer_sock.send(Attribute.encrypt_pipeline(response))
        elif cmd_parsed[0] == 'rm':
            response = {}
            if cmd_parsed[1] not in Attribute.file_details:
                response = {
                    'payload': 'file: {0} not found!'.format(cmd_parsed[1]),
                    'error': 404
                }
            else:
                metadata = Attribute.file_details[cmd_parsed[1]]
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
                    Attribute.file_details[cmd_parsed[1]]['deleted'] = 'true'
                    request = Attribute.encrypt_pipeline({
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
                            rep_peer_response = Attribute.decrypt_pipeline(rep_peer_sock.recv(1024))
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
                        Attribute.file_details[cmd_parsed[1]]['replicated_peers'].remove(peer)
                    Attribute.user_dummy_data(Attribute.file_details, 'file_details.json')
            print(response)
            peer_sock.send(Attribute.encrypt_pipeline(response))
        elif cmd_parsed[0] == 'restore':          #restoring the file
            response = {}
            if cmd_parsed[1] not in Attribute.file_details:
                response = {
                    'payload': 'file: {0} not found!'.format(cmd_parsed[1]),
                    'error': 404
                }
            else:
                metadata = Attribute.file_details[cmd_parsed[1]]
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
                    for peer in Peer_management.nonrepititive_peers():
                        Attribute.file_details[cmd_parsed[1]]['replicated_peers'].append(peer)
                        response['peers_to_replicate'].append({
                            "IP": Attribute.p_active[peer]["IP"],
                            "PORT": Attribute.p_active[peer]["PORT"]
                        })
                    response['payload'] = 'SIG_REPLICATE'
                Attribute.file_details[cmd_parsed[1]]['deleted'] = 'false'
                peer_sock.send(Attribute.encrypt_pipeline(response))
                Attribute.user_dummy_data(Attribute.file_details, 'file_details.json')
        elif cmd_parsed[0] == 'ls':
            response = {
                'payload': []
            }
            for key, value in Attribute.file_details.items():
                line = ''

                # if file is restricted, or deleted and owner is not the current peer, we will not show the file
                if (value['deleted'] == 'true') and value['owner'] != PEER_ID:
                    continue

                file_name = key

                line += 'd' if value['is_directory'] == 'true' else '-'
                line += ' '

                permission = value['permissions']
                line_suffix = ' ' if permission else 'r* '

                if permission == '1':
                    line_suffix = 'r/w '
                elif permission == '2':
                    line_suffix = 'r/w ' if value['owner'] == PEER_ID else 'r '

                line += line_suffix


                line += file_name
                response['payload'].append(line)
            print(response)
            peer_sock.send(Attribute.encrypt_pipeline(response))
    print(PEER_ID, 'is disconnected!')
    # removing the peer info
    Attribute.p_active.pop(PEER_ID, None)
    Attribute.user_dummy_data(Attribute.p_active, 'p_active.json')

#checking malicious activity
def malicious_activity_checker():
    request = {
        'cmd': 'FILE_LISTING_RQST'
    }
    while True:
        time.sleep(100)
        for peer, value in Attribute.p_active.items():
            print('Checking for malicious activity in {0}'.format(peer))
            peer_IP = value['IP']
            peer_PORT = value['PORT']
            peer_sock = socket(AF_INET, SOCK_STREAM)
            peer_sock.connect((peer_IP, int(peer_PORT)))
            peer_sock.send(Attribute.encrypt_pipeline(request))
            peer_response = Attribute.decrypt_pipeline(peer_sock.recv(1024))
            print(peer_response)
            red_flag = False

            # checking the maliciously deleted files
            for key, value in Attribute.file_details.items():
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
                if file not in Attribute.file_details:
                    red_flag = True

            if red_flag:
                print('{0} has been breached'.format(peer_response['peer_id']))
        print()


def main():
    malicious_activity_checker_thread = Thread(target = Malicious_activity_watcher.malicious_activity_checker)
    malicious_activity_checker_thread.start()
    peer_registration_thread = Thread(target = Peer_management.create_peer)
    peer_registration_thread.start()

    while True:
        peer_sock, address = server_sock.accept()
        peer_request_processor_thread = Thread(target = process_peer_request, args=(peer_sock, address))
        peer_request_processor_thread.setDaemon(True)
        peer_request_processor_thread.start()

if __name__ == '__main__':
    main()

server_sock.close()