import base64
import os
import sys
import time
import json
from socket import *
from threading import *
from cryptography.fernet import Fernet

file_path = os.path.dirname(os.path.realpath(__file__))

CDS_IP = 'localhost'

CDS_PORT_NUM = int(sys.argv[2]) if len(sys.argv) > 2 and int(sys.argv[2]) else 8080

IP = 'localhost'

PORT = int(sys.argv[1]) if len(sys.argv) > 1 and int(sys.argv[1]) else 8010


with open('authentication_key.txt', 'r') as f:
    session_key = f.read()

peer_key = Fernet.generate_key()
peer_fernet_enc_dec = Fernet(peer_key)

p_sock = socket(AF_INET, SOCK_STREAM)
p_sock.bind((IP, PORT))
p_sock.listen(5)

peer_id = ''

entity_mapper = {}

#encrypting code
def encrypt_pipeline(json_obj):
    with open('authentication_key.txt', 'r') as f:   #reading the line
        key = f.read()
    try:
        decoded_key_str = base64.urlsafe_b64decode(key)
        fernet_enc_dec = Fernet(decoded_key_str)
        cipher = fernet_enc_dec.encrypt(json.dumps(json_obj).encode('ascii'))
        return cipher
    except:
        print("not allowed")

#decrypting the code
def decrypt_pipeline(cipher):
    with open('authentication_key.txt', 'r') as f:       #reading the line
        time.sleep(1)
        key = f.read()
    try:
        decoded_key_str = base64.urlsafe_b64decode(key)
        fernet_enc_dec = Fernet(decoded_key_str)
        dictionary = json.loads(fernet_enc_dec.decrypt(cipher).decode('ascii'))
        return dictionary
    except:
        print("not allowed")


def menu_list():
    print("\n----------------Commands---------------")
    print("touch [filename] [username with r/w] - Create a new file")
    print("mkdir [dirname] - Create a new directory")
    print("ls - List all files and directories")
    print("cat [filename] - Write text to a file")
    print("read [filename] - Read the contents of a file")
    print("rm [filename] - Delete a file")
    print("rmdir [dirname] - Delete a directory")
    print("restore [filename] - Restore a deleted file")
    print("revocate - revocate the key")
    print("<quit> - Quit the application")
    print("-------------------------------------")

def menu_inputs(choice):
    args_mapper = {
        'touch': 2,
        'cat': 1,
        'read': 1,
        'rm': 1,
        'restore': 1,
        'ls': 0,
        'rmdir': 1,
        'mkdir': 2,
        '<quit>': 0,
        'revocate': 0
    }

    args = choice.split(' ')

    if args[0] in args_mapper:
        #print(args)
        #print(args_mapper)
        if len(args) != args_mapper[args[0]] + 1:
            print('{0}: Invalid Format'.format(args[0]))
            time.sleep(3)
            return False
        if args[0] == 'cat':
            (file_name, file_extension) = os.path.splitext(args[1])
            if not file_extension:
                print('{0}: is not a writable file'.format(file_name))
                time.sleep(3)
                return False
    else:
        print('\'{0}\' is not a valid command'.format(args[0]))
        time.sleep(3)
        return False
    return True

def menu():
    server_sock = socket(AF_INET, SOCK_STREAM)
    server_sock.connect((CDS_IP, int(CDS_PORT_NUM)))

    while True:
        username = input('username: >> ')
        password = input('password: >> ')
        server_sock.send(encrypt_pipeline({
            'username': username,
            'password': password
        }))
        CDS_response = decrypt_pipeline(server_sock.recv(1024))
        print(CDS_response['payload'])
        if 'error' not in CDS_response:
            break

    server_sock.send(encrypt_pipeline({
        'IP': IP,
        'PORT': str(PORT)
    }))
    CDS_response = decrypt_pipeline(server_sock.recv(1024))
    print(CDS_response)
    print(CDS_response['message'])

    global peer_id
    peer_id = CDS_response['peer_id']
    path = os.path.join(file_path, str(peer_id))
    if not os.path.exists(path):
        os.mkdir(path)

    time.sleep(2)
    cmd = ''

    while '<quit>' not in cmd:
        menu_list()
        cmd = input('>> ')
        while not cmd.startswith("touch") and not menu_inputs(cmd):
            menu_list()
            cmd = input('>> ')
        if cmd!='revocate':
            server_sock.send(encrypt_pipeline({
                'cmd': cmd
            }))
        cmd_parsed = cmd.split()

        if cmd_parsed[0] == 'touch':
            print("File has been created successfully")
            CDS_response = decrypt_pipeline(server_sock.recv(1024))

            if 'error' in CDS_response:
                print(CDS_response['payload'])
                time.sleep(2)
                continue

            (file_name, file_extension) = os.path.splitext(cmd_parsed[1])
            encrypted_file_name = peer_fernet_enc_dec.encrypt(file_name.encode('ascii')).decode('ascii') + file_extension
            path = os.path.join(file_path, peer_id, encrypted_file_name)
            f = open(path, 'w')
            f.close()
            entity_mapper[cmd_parsed[1]] = encrypted_file_name

            request = {
                'cmd': cmd
            }
            print(CDS_response)
            for key, value in CDS_response.items():
                peer_IP = value['IP']
                peer_PORT = value['PORT']
                print('Creating {0} @ {1}:{2}'.format(cmd_parsed[1], peer_IP, peer_PORT))
                peer_sock = socket(AF_INET, SOCK_STREAM)
                peer_sock.connect((peer_IP, int(peer_PORT)))
                peer_sock.send(encrypt_pipeline(request))
                print('{0} replicated the file successfully in our system'.format(key))
                peer_sock.close()
                time.sleep(1)
        elif cmd_parsed[0] == 'mkdir':
            CDS_response = decrypt_pipeline(server_sock.recv(1024))

            if 'error' in CDS_response:
                print(CDS_response['payload'])
                time.sleep(2)
                continue

            encrypted_folder= peer_fernet_enc_dec.encrypt(cmd_parsed[1].encode('ascii')).decode('ascii')
            path = os.path.join(file_path, peer_id, encrypted_folder)
            os.mkdir(path)
            entity_mapper[cmd_parsed[1]] = encrypted_folder

            request = {
                'cmd': cmd
            }
            for key, value in CDS_response.items():
                peer_IP = value['IP']
                peer_PORT = value['PORT']
                print('Creating @ {0}:{1}'.format(peer_IP, peer_PORT))
                peer_sock = socket(AF_INET, SOCK_STREAM)
                peer_sock.connect((peer_IP, int(peer_PORT)))
                peer_sock.send(encrypt_pipeline(request))
                print('{0} replicated file successfully'.format(key))
                peer_sock.close()
                time.sleep(1)
        elif cmd_parsed[0] == 'rmdir':
            CDS_response = decrypt_pipeline(server_sock.recv(1024))

            if 'error' in CDS_response:
                print(CDS_response['payload'])
                time.sleep(2)
                continue

            request = {
                'cmd': cmd
            }
            for key, value in CDS_response.items():
                peer_IP = value['IP']
                peer_PORT = value['PORT']
                print('Connecting to {0} using {1}:{2}'.format(key, peer_IP, peer_PORT))
                peer_sock = socket(AF_INET, SOCK_STREAM)
                peer_sock.connect((peer_IP, int(peer_PORT)))
                peer_sock.send(encrypt_pipeline(request))
                print('{0} replicated file successfully in the system'.format(key))
                peer_sock.close()
                time.sleep(1)
        elif cmd == 'revocate':
            session_key = Fernet.generate_key()
            encoded_key = base64.urlsafe_b64encode(session_key)
            encoded_key_str = encoded_key.decode('utf-8')
            with open('authentication_key.txt', 'w') as f:
                f.write(encoded_key_str)
            print("Key revocation completed!")
        elif cmd_parsed[0] == 'cat':
            CDS_response = decrypt_pipeline(server_sock.recv(1024))
            if 'error' in CDS_response:
                print(CDS_response['payload'])
                time.sleep(3)
            else:
                content = ''
                inp = ''
                print('Typing the content...')
                print('<exit> to quit')
                file_enc = Fernet(eval(CDS_response['encryption_key']))
                while True:
                    inp = input()
                    if inp == '<exit>':
                        break
                    content += inp + '\n'

                encrypted_content = str(file_enc.encrypt(content.encode('ascii')))
                encrypted_file = entity_mapper[cmd_parsed[1]]
                path = os.path.join(file_path, peer_id, encrypted_file)
                f = open(path, 'w+')
                f.write(encrypted_content)
                f.close()
                print('Write to file successful')

                request = {
                    'cmd': cmd,
                    'payload': encrypted_content
                }
                for key, value in CDS_response['replicated_peer_info'].items():
                    peer_IP = value['IP']
                    peer_PORT = value['PORT']
                    print('Writing @ {0}:{1}'.format(peer_IP, peer_PORT))
                    peer_sock = socket(AF_INET, SOCK_STREAM)
                    peer_sock.connect((peer_IP, int(peer_PORT)))
                    peer_sock.send(encrypt_pipeline(request))
                    print('{0}: write to {1} successful'.format(key, cmd_parsed[1]))
                    time.sleep(1)
                server_sock.send(encrypt_pipeline({
                    'payload': 'WRITE_ACK'
                }))
        elif cmd_parsed[0] == 'read':
            CDS_response = decrypt_pipeline(server_sock.recv(1024))
            if 'error' in CDS_response:
                print(CDS_response['payload'])
            else:
                found_content = False
                if peer_id in CDS_response['replicated_peer_info']:
                    encrypted_file_name = entity_mapper[cmd_parsed[1]]
                    path = os.path.join(file_path, peer_id, encrypted_file_name)
                    found_content = False

                    if os.path.exists(path):
                        print('file: {0} found in the peer itself'.format(cmd_parsed[1]))
                        file_enc = Fernet(eval(CDS_response['encryption_key']))
                        lines = []
                        content = ''

                        with open(path, 'r') as f:
                            lines = f.readlines()

                        if len(lines) != 0:
                            decrypted_text = file_enc.decrypt(eval(lines[0])).decode('ascii')
                            print(decrypted_text)
                        else:
                            print('<file is empty>')
                        found_content = True

                request = {
                    'cmd': cmd
                }
                for key, value in CDS_response['replicated_peer_info'].items():
                    if found_content:
                        break
                    peer_IP = value['IP']
                    peer_PORT = value['PORT']
                    print('Connecting to {0} using {1}:{2}'.format(key, peer_IP, peer_PORT))
                    peer_sock = socket(AF_INET, SOCK_STREAM)
                    peer_sock.connect((peer_IP, int(peer_PORT)))
                    peer_sock.send(encrypt_pipeline(request))
                    peer_response = decrypt_pipeline(peer_sock.recv(1024))
                    if 'error' in peer_response:
                        print(peer_response['payload'])
                    else:
                        if len(peer_response['payload']) != 0:
                            file_enc = Fernet(eval(CDS_response['encryption_key']))
                            decrypted_text = file_enc.decrypt(eval(peer_response['payload'][0])).decode('ascii')
                            print(decrypted_text)
                        else:
                            print('<file empty>')
                        found_content = True
                    time.sleep(1)
        elif cmd_parsed[0] == 'rm':
            CDS_response = decrypt_pipeline(server_sock.recv(1024))
            if 'error' in CDS_response:
                print(CDS_response['payload'])
            else:
                print(CDS_response['payload'])
        elif cmd_parsed[0] == 'restore':
            CDS_response = decrypt_pipeline(server_sock.recv(1024))
            if 'error' in CDS_response:
                print(CDS_response['payload'])
            elif CDS_response['payload'] == 'SIG_REPLICATE':
                encrypted_file_name = entity_mapper[cmd_parsed[1]]
                path = os.path.join(file_path, peer_id, encrypted_file_name)
                request = {}
                if not os.path.exists(path):
                    print('Umm... seems like the file is deleted at the owner')
                else:
                    with open(path, 'r') as f:
                        lines = f.readlines()
                    content = ''
                    for line in lines:
                        content += line
                    request = {
                        'cmd': cmd,
                        'payload': content
                    }
                    f.close()
                    for peer_to_replicate in CDS_response['peers_to_replicate']:
                        peer_IP = peer_to_replicate['IP']
                        peer_PORT = peer_to_replicate['PORT']
                        print('Replicating @ {0}:{1}'.format(peer_IP, peer_PORT))
                        peer_sock = socket(AF_INET, SOCK_STREAM)
                        peer_sock.connect((peer_IP, int(peer_PORT)))
                        peer_sock.send(encrypt_pipeline(request))
                        time.sleep(1)
        elif cmd_parsed[0] == 'ls':
            CDS_response = decrypt_pipeline(server_sock.recv(1024))
            for line in CDS_response['payload']:
                print(line)
        time.sleep(2)
    server_sock.close()

def peer_to_peer_request_handler(peer_sock, address):
    peer_req = decrypt_pipeline(peer_sock.recv(1024))
    if not peer_req:
        return

    print('Processing the peer request')
    print('>>', peer_req['cmd'])

    cmd = peer_req['cmd'].split()
    if cmd[0] == 'touch':
        (file_name, file_extension) = os.path.splitext(cmd[1])
        encrypted_file_name = peer_fernet_enc_dec.encrypt(file_name.encode('ascii')).decode('ascii') + file_extension
        path = os.path.join(file_path, peer_id, encrypted_file_name)

        entity_mapper[cmd[1]] = encrypted_file_name
        f = open(path, 'w')
        print('File creation is successful in the system')
        f.close()
    elif cmd[0] == 'mkdir':
        encrypted_folder_name = peer_fernet_enc_dec.encrypt(cmd[1].encode('ascii')).decode('ascii')
        path = os.path.join(file_path, peer_id, encrypted_folder_name)
        os.mkdir(path)

        entity_mapper[cmd[1]] = encrypted_folder_name
    elif cmd[0] == 'rmdir':
        encrypted_folder_name = entity_mapper[cmd[1]]
        path = os.path.join(file_path, peer_id, encrypted_folder_name)
        os.rmdir(path)
    elif cmd[0] == 'cat' or cmd[0] == 'restore':
        encrypted_file_name = entity_mapper[cmd[1]]
        path = os.path.join(file_path, peer_id, encrypted_file_name)
        # extract content
        payload = peer_req['payload']
        f = open(path, 'w+')
        f.write(payload)
        print('update to file is successful')
        f.close()
    elif cmd[0] == 'read':
        encrypted_file_name = entity_mapper[cmd[1]]
        path = os.path.join(file_path, peer_id, encrypted_file_name)
        response = {}
        if not os.path.exists(path):
            response = {
                'error': 404,
                'payload': '{0} could not be located at {1}'.format(cmd[1], peer_id)
            }
        else:
            with open(path, 'r') as f:
                contents = f.readlines()
            response = {
                'payload': contents
            }
            f.close()
        peer_sock.send(encrypt_pipeline(response))
    elif cmd[0] == 'rm':
        encrypted_file_name = entity_mapper[cmd[1]]
        path = os.path.join(file_path, peer_id, encrypted_file_name)
        response = {}
        if not os.path.exists(path):
            response = {
                'error': 404,
                'payload': '{0} could not be located at {1}'.format(cmd[1], peer_id)
            }
        else:
            os.remove(path)
            if not os.path.exists(path):
                response = {
                    'payload': '{0} deleted {1} successfully'.format(peer_id, cmd[1])
                }
            else:
                response = {
                    'error': 400,
                    'payload': 'some issue occured while deleting {0}'.format(cmd[1])
                }
        if 'error' in response:
            print(response['payload'])
        else:
            print(response['payload'])
        peer_sock.send(encrypt_pipeline(response))
    elif cmd[0] == 'FILE_LISTING_RQST':
        path = os.path.join(file_path, peer_id)
        files = os.listdir(path)
        decrypted_file_names = []
        for file in files:
            try:
                (file_name, file_extension) = os.path.splitext(file)
                decrypted_file_name = peer_fernet_enc_dec.decrypt(file_name.encode('ascii')).decode('ascii') + file_extension
                decrypted_file_names.append(decrypted_file_name)
            except:
                decrypted_file_names.append(file)
        response = {
            'peer_id': peer_id,
            'file_list': decrypted_file_names
        }
        peer_sock.send(encrypt_pipeline(response))

if __name__ == '__main__':
    menu_thread = Thread(target = menu)
    menu_thread.start()

    while True:
        peer_sock, address = p_sock.accept()
        peer_to_peer_request_handler_thread = Thread(target = peer_to_peer_request_handler, args=(peer_sock, address))
        peer_to_peer_request_handler_thread.start()
