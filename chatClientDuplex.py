#CMPT471 Project: E2E encrypted messaging system using signal protocol
# Andy Ng and Rahul Anand

#requires pycryptodome
import os   #for exit
import time     #for stalling
from tools import User  
import pickle      # used for pickling objects (such as messages) into a bytestream so that we can send via socket
from Crypto.Cipher import AES       #for encryption
from socket import AF_INET, socket, SOCK_STREAM     #for socket handling
from threading import Thread           # used for creating a thread for accepting connections

connectionAuthenticated = False

"""constants"""
HOST = 'localhost'          #must match chatServerDuplex
PORT = 65535                #must match chatServerDuplex
ENCODING_TYPE = 'utf-8'
ADDRESS = (HOST, PORT)
HEADER_LEN=10
USERNAME_LEN=50

"""Diffie-Hellman Key Exchange"""
def DHkeyExchange(user,pKeys):
    user.computeSharedKeys(pKeys)
    user.encryptKeys()

""" To send a message, the function needs the 
    - message,  
    - and whether or not hte msg is encoded or encrypted"""
def sendMsg(msg, encoded = False, encrypt = False):
    if not encoded:
        msg = msg.encode(ENCODING_TYPE)
    #AES
    if encrypt: 
        cipher = AES.new(user.userKey, AES.MODE_EAX)
        nonce = cipher.nonce
        encryptedMessage, tag = cipher.encrypt_and_digest(msg)
        msg=pickle.dumps((nonce,encryptedMessage,tag))
           
    msg_header = f"{len(msg):<{HEADER_LEN}}".encode(ENCODING_TYPE)
    client_socket.send(msg_header + msg)

""" To handle a received message, the function needs the 
    - the present client, 
    - and if the msg is encoded"""
def receiveMsg(client, encoded = False):
    try:
        msg_header = client.recv(HEADER_LEN)
        if not msg_header:
            print("Header missing")

        msg_len= int(msg_header.decode(ENCODING_TYPE).strip())

        if encoded:
            return client.recv(msg_len)
        else:
            return client.recv(msg_len).decode(ENCODING_TYPE)
    except:
        print ("Header wrong format ", msg_header)


def receive_thread():
    global connectionAuthenticated,user
    while True:
        incMsg = receiveMsg(client_socket,encoded=True)

        try:
            msg = incMsg.decode(ENCODING_TYPE)
        except:
            msg =""

#-----------------------------------------------------------------------------------------------------------------------
# When join is successful
        if msg == "#join success":
            recvInfo = receiveMsg(client_socket, encoded=True)
            info = pickle.loads(recvInfo)
            user = User(info['id'], info['p'], info['g'])
            sendMsg(str(user.publicKey))
#-----------------------------------------------------------------------------------------------------------------------
# Exiting
        elif msg == "#exit":
            user.encryptKeys()
            print("Exiting...")
            client_socket.close()
            os._exit(1)
#-----------------------------------------------------------------------------------------------------------------------
#When new user is announced to all other users
        elif msg[0:len("#notice")] == "#notice":   #all notice messages are prefixed with #notice so remove it
            remove_prefix = msg[len("#notice"):]
            print(remove_prefix)
#-----------------------------------------------------------------------------------------------------------------------
# #new user command
        elif msg == "#new user":
            sendMsg("#new user")
            print ("\nAdding user... ")

            while True:
                try:
                    publicKeys=pickle.loads(receiveMsg(client_socket,encoded=True))
                    #add user to publicKeys
                    if user.id not in publicKeys:
                        publicKeys[user.id] = user.publicKey
                    
                    #Diffie-Hellman Key Exchange
                    DHkeyExchange(user, publicKeys)

                    sendMsg(pickle.dumps(user.encryptedKeys), encoded=True)
                    temp = receiveMsg(client_socket, encoded = True)
                    otherKeys= pickle.loads(temp)
                    user.decryptKeys(otherKeys)

                    connectionAuthenticated = True
                    break

                except:
                    print("Waiting for server...")
                    time.sleep(0.5)
#-----------------------------------------------------------------------------------------------------------------------       
#If not a command AKA a message
        else:
            if connectionAuthenticated:
                sendingUser = incMsg[:USERNAME_LEN].decode(ENCODING_TYPE).strip()
                skip = False

                try:    #handling received message
                    receivedNonce,receivedMsg,receivedTag = pickle.loads(incMsg[USERNAME_LEN:])
                    
                except EOFError:
                    print(">> " + sendingUser + " empty input, try again")
                    skip = True   #skip if it's an empty input

                if skip == False:  #non empty input
                    if sendingUser == user.id:  #if client is sender
                        decipher = AES.new(user.userKey, AES.MODE_EAX,nonce=receivedNonce)
                        decryptedReceivedMsg = decipher.decrypt(receivedMsg)
                        decipher.verify(receivedTag)
                        print(sendingUser + ": " + decryptedReceivedMsg.decode(ENCODING_TYPE))        #shows the msg in command line

                    else: #if client is not sender
                        decipher = AES.new(user.decryptedKeys[sendingUser], AES.MODE_EAX,nonce=receivedNonce)
                        decryptedReceivedMsg = decipher.decrypt(receivedMsg)
                        decipher.verify(receivedTag)
                        print(sendingUser + ": " + decryptedReceivedMsg.decode(ENCODING_TYPE))    #shows the msg in command line

            else:
                print(msg)

def send_thread():
    while True:
        msg = input("> ")
        #move the cursor up twice for formatting purposes on CLI and avoid duplicate messages
        print ("\033[A                                                   \033[A")
        if(connectionAuthenticated and msg != "#exit"):
            sendMsg(msg,encrypt=True)
        else:
            sendMsg(msg)

#main socket code that is run
client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect(ADDRESS)

r_thread = Thread(target=receive_thread)
r_thread.start()

s_thread = Thread(target=send_thread)
s_thread.start()
