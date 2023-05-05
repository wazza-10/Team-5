import os
import time
import base64
import json
from cryptography.fernet import Fernet
# Server side
#Attributes declaration
User_IP = 'localhost'
REPLICATION_FACTOR = 3

p_active = {}

file_details = {}
user_credentials = {}
curr_file_path = os.path.dirname(os.path.realpath(__file__))

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

def user_dummy_data(file_content, path):
    path = os.path.join(curr_file_path, path)
    with open(path, "w") as write_file:
        json.dump(file_content, write_file, indent=4)

# Client Side

#Attributes declaration
#creating peer_id variable
peer_id = ''

user_entity_mapper = {}
CDS_IP = 'localhost'
IP = 'localhost'
#generating key using fernet
peer_key = Fernet.generate_key()
peer_fernet_enc_dec = Fernet(peer_key)


#encrypting code and decrypting code
def encrypt_pipeline_client(json_obj):
    with open('authentication_key.txt', 'r') as f:
        key = f.read()
    try:
        decoded_key_str = base64.urlsafe_b64decode(key)
        fernet_enc_dec = Fernet(decoded_key_str)
        cipher = fernet_enc_dec.encrypt(json.dumps(json_obj).encode('ascii'))
        return cipher
    except:
        print("Authentication error")

def decrypt_pipeline_client(cipher):
    with open('authentication_key.txt', 'r') as f:
        time.sleep(1)
        key = f.read()
    try:
        decoded_key_str = base64.urlsafe_b64decode(key)
        fernet_enc_dec = Fernet(decoded_key_str)
        dictionary = json.loads(fernet_enc_dec.decrypt(cipher).decode('ascii'))
        return dictionary
    except:
        print("Authentication error")