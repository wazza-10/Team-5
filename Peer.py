import base64
import os
import sys
import time
import Attribute
from socket import *
from threading import *
from cryptography.fernet import Fernet



#port check
if len(sys.argv) > 2 and int(sys.argv[2]):
    CDS_PORT = int(sys.argv[2])
else:
    CDS_PORT = 8080


IP = 'localhost'

if len(sys.argv) > 1 and int(sys.argv[1]):
    PORT = int(sys.argv[1])
else:
    PORT = 8010


with open('authentication_key.txt', 'r') as f:
    session_key = f.read()


#socket connection
p_sock = socket(AF_INET, SOCK_STREAM)
p_sock.bind((IP, PORT))
p_sock.listen(5)



def user_menu_list():
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

    #input validation
    if args[0] in args_mapper:
        if len(args) != args_mapper[args[0]] + 1:
            print('{0}: Invalid Format'.format(args[0]))
            time.sleep(2)
            return False
        if args[0] == 'cat':
            (file_name, file_extension) = os.path.splitext(args[1])
            if not file_extension:
                print('{0}: is not a writable file'.format(file_name))
                time.sleep(2)
                return False
    else:
        print('\'{0}\' is not a valid command'.format(args[0]))
        time.sleep(2)
        return False
    return True

def menu():
    CDS_sock = socket(AF_INET, SOCK_STREAM)  #cds connection
    CDS_sock.connect((Attribute.CDS_IP, int(CDS_PORT))) #connection made

    while True:
        username = input('username: >> ')
        password = input('password: >> ')
        try:
            #sending to cds
            CDS_sock.send(Attribute.encrypt_pipeline_client({
                'username': username,
                'password': password
            }))
            #getting response
            CDS_response = Attribute.decrypt_pipeline_client(CDS_sock.recv(1024))
            print(CDS_response['payload'])
            if 'error' not in CDS_response:
                break
        except:
            pass

    CDS_sock.send(Attribute.encrypt_pipeline_client({
        'IP': IP,
        'PORT': str(PORT)
    }))
    CDS_response = Attribute.decrypt_pipeline_client(CDS_sock.recv(1024))
    #printing CDS response
    print(CDS_response)
    print(CDS_response['message'])

    global peer_id
    peer_id = CDS_response['peer_id']
    path = os.path.join(Attribute.curr_file_path, str(peer_id))
    if not os.path.exists(path):
        os.mkdir(path)

    time.sleep(1)
    cmd = ''

    #Using quit command
    while '<quit>' not in cmd:
        try:
            user_menu_list()
            cmd = input('>> ')
            while not cmd.startswith("touch") and not menu_input_valid(cmd):
                user_menu_list()
                cmd = input('>> ')
            if cmd!='revocate':  #added revocate option in user menu
                CDS_sock.send(Attribute.encrypt_pipeline_client({
                    'cmd': cmd
                }))
            cmd_parsed = cmd.split()

            if cmd_parsed[0] == 'touch':
                print("File has been created successfully")
                CDS_response = Attribute.decrypt_pipeline_client(CDS_sock.recv(1024))

                if 'error' in CDS_response:
                    print(CDS_response['payload'])
                    time.sleep(4)
                    continue

                (file_name, file_extension) = os.path.splitext(cmd_parsed[1])
                encrypted_file_name = Attribute.peer_fernet_enc_dec.encrypt(file_name.encode('ascii')).decode('ascii') + file_extension
                path = os.path.join(Attribute.curr_file_path, peer_id, encrypted_file_name)
                f = open(path, 'w')
                f.close()
                Attribute.user_entity_mapper[cmd_parsed[1]] = encrypted_file_name

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
                    peer_sock.send(Attribute.encrypt_pipeline_client(request))
                    print('{0} replicated the file successfully in the system'.format(key))
                    peer_sock.close()
                    time.sleep(1)
            elif cmd_parsed[0] == 'mkdir':           #creating directory
                CDS_response = Attribute.decrypt_pipeline_client(CDS_sock.recv(1024))

                if 'error' in CDS_response:
                    print(CDS_response['payload'])
                    time.sleep(3)
                    continue

                encrypted_folder_name = Attribute.peer_fernet_enc_dec.encrypt(cmd_parsed[1].encode('ascii')).decode('ascii')
                path = os.path.join(Attribute.curr_file_path, peer_id, encrypted_folder_name)
                os.mkdir(path)
                Attribute.user_entity_mapper[cmd_parsed[1]] = encrypted_folder_name

                request = {
                    'cmd': cmd
                }
                for key, value in CDS_response.items():
                    peer_IP = value['IP']
                    peer_PORT = value['PORT']
                    print('Creating @ {0}:{1}'.format(peer_IP, peer_PORT))
                    peer_sock = socket(AF_INET, SOCK_STREAM)
                    peer_sock.connect((peer_IP, int(peer_PORT)))
                    peer_sock.send(Attribute.encrypt_pipeline_client(request))
                    print('{0} replicated the file successfully in the system'.format(key))
                    peer_sock.close()
                    time.sleep(3)
            elif cmd_parsed[0] == 'rmdir':          #removing the directory
                CDS_response = Attribute.decrypt_pipeline_client(CDS_sock.recv(1024))

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
                    peer_sock.send(Attribute.encrypt_pipeline_client(request))
                    print('{0} replicated the file successfully in the system'.format(key))
                    peer_sock.close()
                    time.sleep(2)
            elif cmd == 'revocate':   #key revocation
                session_key = Fernet.generate_key()
                encoded_key = base64.urlsafe_b64encode(session_key)
                encoded_key_str = encoded_key.decode('utf-8')
                with open('authentication_key.txt', 'w') as f:
                    f.write(encoded_key_str)
                print("Key revocation completed!")
            elif cmd_parsed[0] == 'cat':
                CDS_response = Attribute.decrypt_pipeline_client(CDS_sock.recv(1024))
                if 'error' in CDS_response:
                    print(CDS_response['payload'])
                    time.sleep(2)
                else:
                    content = ''
                    inp = ''
                    print('Type the content...')
                    print('<exit> to quit')
                    file_enc = Fernet(eval(CDS_response['encryption_key']))
                    content = ''
                    while True:
                        inp = input()
                        if inp == '<exit>':
                            break
                        content += inp + '\n'


                    encrypted_content = str(file_enc.encrypt(content.encode('ascii')))
                    encrypted_file_name = Attribute.user_entity_mapper[cmd_parsed[1]]
                    path = os.path.join(Attribute.curr_file_path, peer_id, encrypted_file_name)
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
                        peer_sock.send(Attribute.encrypt_pipeline_client(request))
                        print('{0}: write to {1} successful'.format(key, cmd_parsed[1]))
                        time.sleep(1)
                    CDS_sock.send(Attribute.encrypt_pipeline_client({
                        'payload': 'WRITE_ACK'
                    }))
            elif cmd_parsed[0] == 'read':
                CDS_response = Attribute.decrypt_pipeline_client(CDS_sock.recv(1024))
                if 'error' in CDS_response:
                    print(CDS_response['payload'])
                else:
                    found_content = False
                    if peer_id in CDS_response['replicated_peer_info']:
                        encrypted_file_name = Attribute.user_entity_mapper[cmd_parsed[1]]
                        path = os.path.join(Attribute.curr_file_path, peer_id, encrypted_file_name)
                        found_content = False

                        if os.path.exists(path):
                            print('file: {0} found in the peer itself'.format(cmd_parsed[1]))
                            file_enc = Fernet(eval(CDS_response['encryption_key']))
                            lines = []
                            content = ''

                            with open(path, 'r') as f:
                                lines = f.readlines()

                            decrypted_text = file_enc.decrypt(eval(lines[0])).decode('ascii') if len(lines) != 0 else '<file empty>'
                            print(decrypted_text)

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
                        peer_sock.send(Attribute.encrypt_pipeline_client(request))
                        peer_response = Attribute.decrypt_pipeline_client(peer_sock.recv(1024))
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
                        time.sleep(3)
            elif cmd_parsed[0] == 'rm':
                CDS_response = Attribute.decrypt_pipeline_client(CDS_sock.recv(1024))
                if 'error' in CDS_response:
                    print(CDS_response['payload'])
                else:
                    print(CDS_response['payload'])
            elif cmd_parsed[0] == 'restore':     #restoring the file
                CDS_response = Attribute.decrypt_pipeline_client(CDS_sock.recv(1024))
                if 'error' in CDS_response:
                    print(CDS_response['payload'])
                elif CDS_response['payload'] == 'SIG_REPLICATE':
                    encrypted_file_name = Attribute.user_entity_mapper[cmd_parsed[1]]
                    path = os.path.join(Attribute.curr_file_path, peer_id, encrypted_file_name)
                    request = {}
                    if not os.path.exists(path):
                        print('It appears that the owner has deleted the file.')
                    else:
                        with open(path, 'r') as file:
                            lines = file.readlines()
                        content = ''
                        for line in lines:
                            content += line
                        request = {
                            'cmd': cmd,
                            'payload': content
                        }
                        file.close()
                        for peer_to_replicate in CDS_response['peers_to_replicate']:
                            peer_IP = peer_to_replicate['IP']
                            peer_PORT = peer_to_replicate['PORT']
                            print('Replicating @ {0}:{1}'.format(peer_IP, peer_PORT))
                            peer_sock = socket(AF_INET, SOCK_STREAM)
                            peer_sock.connect((peer_IP, int(peer_PORT)))
                            peer_sock.send(Attribute.encrypt_pipeline_client(request))
                            time.sleep(1)
            elif cmd_parsed[0] == 'ls':
                CDS_response = Attribute.decrypt_pipeline_client(CDS_sock.recv(1024))
                for line in CDS_response['payload']:
                    print(line)
            time.sleep(4)
        except:
            cmd=""
    CDS_sock.close()

def peer_to_peer_request_handler(peer_sock, address):
    peer_req = Attribute.decrypt_pipeline_client(peer_sock.recv(1024))
    if not peer_req:
        return

    print('Processing the peer request')
    print('>>', peer_req['cmd'])

    cmd = peer_req['cmd'].split()
    if cmd[0] == 'touch':
        (file_name, file_extension) = os.path.splitext(cmd[1])
        encrypted_file_name = Attribute.peer_fernet_enc_dec.encrypt(file_name.encode('ascii')).decode('ascii') + file_extension
        path = os.path.join(Attribute.curr_file_path, peer_id, encrypted_file_name)

        Attribute.user_entity_mapper[cmd[1]] = encrypted_file_name
        f = open(path, 'w')
        print('File creation successful')
        f.close()
    elif cmd[0] == 'mkdir':
        encrypted_folder_name = Attribute.peer_fernet_enc_dec.encrypt(cmd[1].encode('ascii')).decode('ascii')
        path = os.path.join(Attribute.curr_file_path, peer_id, encrypted_folder_name)
        os.mkdir(path)

        Attribute.user_entity_mapper[cmd[1]] = encrypted_folder_name
    elif cmd[0] == 'rmdir':
        encrypted_folder_name = Attribute.user_entity_mapper[cmd[1]]
        path = os.path.join(Attribute.curr_file_path, peer_id, encrypted_folder_name)
        os.rmdir(path)
    elif cmd[0] == 'cat' or cmd[0] == 'restore':
        encrypted_file_name = Attribute.user_entity_mapper[cmd[1]]
        path = os.path.join(Attribute.curr_file_path, peer_id, encrypted_file_name)
        # extract content
        payload = peer_req['payload']
        f = open(path, 'w+')
        f.write(payload)
        print('Write to file successful')
        f.close()
    elif cmd[0] == 'read':
        encrypted_file_name = Attribute.user_entity_mapper[cmd[1]]
        path = os.path.join(Attribute.curr_file_path, peer_id, encrypted_file_name)
        response = {}
        if not os.path.exists(path):
            response = {
                'error': 404,
                'payload': '{0} could not be located at {1}'.format(cmd[1], peer_id)
            }
        else:
            with open(path, 'r') as file:
                contents = file.readlines()
            response = {
                'payload': contents
            }
            file.close()
        peer_sock.send(Attribute.encrypt_pipeline_client(response))
    elif cmd[0] == 'rm':
        encrypted_file_name = Attribute.user_entity_mapper[cmd[1]]
        path = os.path.join(Attribute.curr_file_path, peer_id, encrypted_file_name)
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
                    'payload': 'There was a problem encountered during the deletion process. {0}'.format(cmd[1])
                }
        if 'error' in response:
            print(response['payload'])
        else:
            print(response['payload'])
        peer_sock.send(Attribute.encrypt_pipeline_client(response))
    elif cmd[0] == 'FILE_LISTING_RQST':
        path = os.path.join(Attribute.curr_file_path, peer_id)
        files = os.listdir(path)
        decrypted_file_names = []
        for file in files:
            try:
                (file_name, file_extension) = os.path.splitext(file)
                decrypted_file_name = Attribute.peer_fernet_enc_dec.decrypt(file_name.encode('ascii')).decode('ascii') + file_extension
                decrypted_file_names.append(decrypted_file_name)
            except:
                decrypted_file_names.append(file)
        response = {
            'peer_id': peer_id,
            'file_list': decrypted_file_names
        }
        peer_sock.send(Attribute.encrypt_pipeline_client(response))

if __name__ == '__main__':
    menu_thread = Thread(target = menu)
    menu_thread.start()

    while True:
        peer_sock, address = p_sock.accept()
        peer_to_peer_request_handler_thread = Thread(target = peer_to_peer_request_handler, args=(peer_sock, address))
        peer_to_peer_request_handler_thread.start()
