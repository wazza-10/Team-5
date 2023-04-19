import os
import sys
import time
import json
from socket import *
from threading import *
from cryptography.fernet import Fernet

curr_path = os.path.dirname(os.path.realpath(__file__))

CDS_IP = 'localhost'
CDS_PORT = int(sys.argv[2]) if len(sys.argv) > 2 and int(sys.argv[2]) else 8080

IP = 'localhost'
PORT = int(sys.argv[1]) if len(sys.argv) > 1 and int(sys.argv[1]) else 8010

pre_agreed_key = b'Z4-L_1FMlhMiHJgNtI5hCyry2nV6-brcEW2lOsFZ7K8='
fernet_enc_dec = Fernet(pre_agreed_key)

peer_key = Fernet.generate_key()
peer_fernet_enc_dec = Fernet(peer_key)

p_sock = socket(AF_INET, SOCK_STREAM)
p_sock.bind((IP, PORT))
p_sock.listen(5)

# peer identifier assigned by server
peer_id = ''

entity_mapper = {}

'''
    converts a python dictionary to an encrypted text
    dictionary -> json -> encode -> cipher
'''
def encrypt_pipeline(json_obj):
    # print('ep', json_obj)
    cipher = fernet_enc_dec.encrypt(json.dumps(json_obj).encode('ascii'))
    return cipher

'''
    converts a cipher text to a python dictionary
    cipher -> decode -> json -> dictionary
'''
def decrypt_pipeline(cipher):
    # print('dp', cipher)
    dictionary = json.loads(fernet_enc_dec.decrypt(cipher).decode('ascii'))
    return dictionary

def menu_list():
    print("\n----------------MENU---------------")
    print("touch [filename] [access_rights] - Create file")
    print("  access_rights")
    print("    1 - Read & Write (all)")
    print("    2 - Read (all), Write (owner)")
    print("    3 - Restricted")
    print("mkdir [filename] - Create a new folder")
    print("ls - List files")
    print("cat [filename] - Write text to file")
    print("read [filename] - Read contents of file")
    print("rm [filename] - Delete the file")
    print("rmdir [filename] - Delete the folder")
    print("restore [filename] - Restore the file")
    print("<quit> - Quit from the application")
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
        '<quit>': 0
    }

    args = choice.split(' ')

    if args[0] in args_mapper:
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