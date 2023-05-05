import Attribute
import time
import Attribute
from socket import *


#Malicious Acitivty Wacther Class
#checking malicious activity
def malicious_activity_checker():
    request = {
        'cmd': 'FILE_LISTING_RQST'
    }
    while True:
        time.sleep(100)
        for peer, value in Attribute.p_active.items():
            print('Checking for malicious activity in {0}'.format(peer))
            try:
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
            except:
                pass
        print()