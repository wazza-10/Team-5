# thanlau
## Team 5: PCS Project
### Peer to peer distributed file system: 

There is a possibility of traffic if numerous users request data from a single server, thus we will utilize a distributed file system to avoid this problem. The purpose of this project is to create an encrypted peer to peer architecture. Here we should be able to create a file, delete a file, read a file, write a file and restore a file. The filenames and the communication between the peers has to be encrypted. The user should have the key revocation functionality and if any malicious activity is happening then we have to detect it. 

### Libraries: 

Socket:  The Python socket module offers low-level network communication capabilities that let programs talk with one another using a range of network protocols. It offers a collection of classes and functions for creating, modifying, and interacting with sockets, which are network endpoints used for transmitting and receiving data.

Threading: The threading module in Python offers a method for creating and controlling threads. It is a built-in module that enables concurrent task execution by enabling thread creation and use in Python scripts.

Cryptography.fernet: The Popular Python library, the cryptography module, offers a number of cryptographic functionalities, such as encryption, decryption, digital signatures, and key exchange.The cryptography offered the Fernet class.Users can create and maintain Fernet keys with the fernet module as well as utilize those keys to encrypt and decode data.

### Installing:

Executing in terminal: You must have the python version 3 or above and add the python executeable path to the environmental variables.
Running in visual studio code: Add the extension in the vs code and you can run the file

### Commands:

Start the CDS server using "python .\cds.py"
Start the peer server using "python .\peer.py"
After starting the peer server authenticate the user using credentials
For example,
Username:shashank
Password:pass
Then, we will have the menu

----------------Commands---------------

touch [filename] [username with r/w] - Create a new file

mkdir [dirname] - Create a new directory

ls - List all files and directories

cat [filename] - Write text to a file

read [filename] - Read the contents of a file

rm [filename] - Delete a file

rmdir [dirname] - Delete a directory

restore [filename] - Restore a deleted file

revocate - revocate the key

quit - Quit the application

-------------------------------------

For example: filename=team5, foldername=pcs

Create a file using "touch" command and followed by access rights to the peers - touch team5.txt peer_2 r peer_3 w

Write a file using "cat" command - cat team5.txt

Read a file using "read" command - read team5.txt

Remove that file using "rm" command - rm team5.txt

Create a folder using "mkdir" command - mkdir pcs.txt

Remove the folder using "rmdir"command - rmdir pcs.txt

For the restore, only the owner of the file can restore it.

Restore a file using "restore" command - restore team5.txt

If the user want to quit from the application enter quit>

If the user want to revocate the key then do revocate

