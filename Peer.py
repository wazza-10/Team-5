import base64
import os
import sys
import time
import json
from socket import *
from threading import *
from cryptography.fernet import Fernet

curr_path = os.path.dirname(os.path.realpath(__file__))

CDS_IP = 'localhost'
print(sys.argv)
CDS_PORT = int(sys.argv[2]) if len(sys.argv) > 2 and int(sys.argv[2]) else 8080

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

def encrypt_pipeline(json_obj):
    with open('authentication_key.txt', 'r') as f:
        key = f.read()
    try:
        decoded_key_str = base64.urlsafe_b64decode(key)
        fernet_enc_dec = Fernet(decoded_key_str)
        cipher = fernet_enc_dec.encrypt(json.dumps(json_obj).encode('ascii'))
        return cipher
    except:
        print("not allowed")


def decrypt_pipeline(cipher):
    # print('dp', cipher)
    with open('authentication_key.txt', 'r') as f:
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

def menu_input_valid(choice):
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
        print('\'{0}\' is not a recognized command'.format(args[0]))
        time.sleep(3)
        return False
    return True

def menu():
    CDS_sock = socket(AF_INET, SOCK_STREAM)
    CDS_sock.connect((CDS_IP, int(CDS_PORT)))

    while True:
        username = input('username: >> ')
        password = input('password: >> ')
        CDS_sock.send(encrypt_pipeline({
            'username': username,
            'password': password
        }))
        CDS_response = decrypt_pipeline(CDS_sock.recv(1024))
        print(CDS_response['payload'])
        # login successful
        if 'error' not in CDS_response:
            break

    CDS_sock.send(encrypt_pipeline({
        'IP': IP,
        'PORT': str(PORT)
    }))
    CDS_response = decrypt_pipeline(CDS_sock.recv(1024))
    print(CDS_response)
    print(CDS_response['message'])

    global peer_id
    peer_id = CDS_response['peer_id']
    path = os.path.join(curr_path, str(peer_id))
    if not os.path.exists(path):
        os.mkdir(path)

    time.sleep(2)
    cmd = ''

    while '<quit>' not in cmd:
        menu_list()
        cmd = input('>> ')
        while not cmd.startswith("touch") and not menu_input_valid(cmd):
            menu_list()
            cmd = input('>> ')
        if cmd!='revocate':
            CDS_sock.send(encrypt_pipeline({
                'cmd': cmd
            }))
        cmd_parsed = cmd.split()

        if cmd_parsed[0] == 'touch':
            print("File has been created successfully")
            CDS_response = decrypt_pipeline(CDS_sock.recv(1024))

            if 'error' in CDS_response:
                print(CDS_response['payload'])
                time.sleep(2)
                continue

            (file_name, file_extension) = os.path.splitext(cmd_parsed[1])
            encrypted_file_name = peer_fernet_enc_dec.encrypt(file_name.encode('ascii')).decode('ascii') + file_extension
            path = os.path.join(curr_path, peer_id, encrypted_file_name)
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
                print('{0} replicated file successfully'.format(key))
                peer_sock.close()
                time.sleep(1)
        elif cmd_parsed[0] == 'mkdir':
            CDS_response = decrypt_pipeline(CDS_sock.recv(1024))

            if 'error' in CDS_response:
                print(CDS_response['payload'])
                time.sleep(2)
                continue

            encrypted_folder_name = peer_fernet_enc_dec.encrypt(cmd_parsed[1].encode('ascii')).decode('ascii')
            path = os.path.join(curr_path, peer_id, encrypted_folder_name)
            os.mkdir(path)
            entity_mapper[cmd_parsed[1]] = encrypted_folder_name

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
            CDS_response = decrypt_pipeline(CDS_sock.recv(1024))

            if 'error' in CDS_response:
                print(CDS_response['payload'])
                time.sleep(2)
                continue

            request = {
                'cmd': cmd
            }
            
