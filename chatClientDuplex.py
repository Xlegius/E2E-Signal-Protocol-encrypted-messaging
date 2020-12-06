import sys
import os
import time
from utils import User,CIPHER_KEYSIZE,KeyDerivationFunction
import pickle
from Crypto.Cipher import AES
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread

authenticated = False

def send (msg, client, raw = False, encrypt = False):
    if not raw:
        msg = msg.encode('utf-8')

    if encrypt: 
        aes = AES.new(user.senderKey, AES.MODE_EAX)
        encryptedMessage, tag = aes.encrypt_and_digest(msg)
        nonce = aes.nonce
        msg=pickle.dumps((nonce,encryptedMessage,tag))
        
    msg_header = f"{len(msg):<{HEADER_LENGTH}}".encode('utf-8')
    client_socket.send(msg_header + msg)

def receive(client, raw = False):
    try:
        msg_header = client.recv(HEADER_LENGTH)
        if not msg_header:
            print("Header missing")

        msg_len= int(msg_header.decode('utf-8').strip())

        if raw:
            return client.recv(msg_len)
        else:
            return client.recv(msg_len).decode('utf-8')
    except:
        print ("Header wrong format ", msg_header)

def checkCMD(cmd,msg):
    checkMsg = msg[0:len(cmd.lower())]
    if (checkMsg == cmd.lower()):
        return True
    return False

def keyExchange(user,pKeys):
    user.computeSharedKeys(pKeys)
    user.encryptKeys()

def receiveThread():
    global authenticated,user
    while True:
        incMsg = receive(client_socket,raw=True)

        try:
            msg = incMsg.decode('utf-8')
        except:
            msg =""

#-----------------------------------------------------------------------------------------------------------------------
        if checkCMD('#signup success', msg):
            infodump = receive(client_socket, raw=True)
            info = pickle.loads(infodump)
            user = User(info['id'], info['p'], info['g'])
            with open("./data/" + user.id, 'wb+') as userfile:
                pickle.dump(user, userfile)
            send(str(user.publicKey), client_socket)

#-----------------------------------------------------------------------------------------------------------------------
        elif checkCMD('#quit', msg):
            user.encryptKeys()

            with open("./data/"+user.id, 'wb+') as userfile:
                pickle.dump(user,userfile)
            print("Terminating connection")
            client_socket.close()
            os._exit(1)
#-----------------------------------------------------------------------------------------------------------------------
        elif checkCMD('#broadcast',msg):
            print(msg[len("#broadcast"):])

#-----------------------------------------------------------------------------------------------------------------------
        elif checkCMD("#new user", msg):
            send ("#new user", client_socket)
            print ("Adding user...")

            while True:
                try:
                    publicKeys=pickle.loads(receive(client_socket,raw=True))
                    if user.id not in publicKeys:
                        publicKeys[user.id] = user.publicKey
                    keyExchange(user, publicKeys)

                    send(pickle.dumps(user.encryptedKeys), client_socket, raw=True)
                    tmp = receive(client_socket, raw = True)
                    otherKeys= pickle.loads(tmp)
                    user.decryptKeys(otherKeys)
                    with open("./data/" + user.id, 'wb+') as userfile:
                        pickle.dump(user, userfile)

                    authenticated = True
                    break
                except:
                    print("Waiting for server, please wait...")
                    time.sleep(0.5)
#-----------------------------------------------------------------------------------------------------------------------       
        else:
            if authenticated:
                originUser = incMsg[:USERNAME_LENGTH].decode('utf-8').strip()

                try:
                    receivedNonce,receivedMsg,receivedTag = pickle.loads(incMsg[USERNAME_LENGTH:])
                except EOFError:
                    print(">>>> " + originUser + " empty input, try again")

                if originUser == user.id:
                    try:
                        decipher = AES.new(user.senderKey, AES.MODE_EAX,nonce=receivedNonce)
                        decryptedReceivedMsg = decipher.decrypt(receivedMsg)
                        try:
                            decipher.verify(receivedTag)
                        except ValueError:
                            time.sleep(0.5)

                        if originUser != user.id:
                            try:
                                print(originUser + ": " + decryptedReceivedMsg.decode('utf-8'))
                                user.decryptedKeys[originUser] = KeyDerivationFunction(user.decryptedKeys[originUser], RATCHETING_STEPS)
                            except UnicodeDecodeError:
                                time.sleep(0.5)
                                #print(originUser + ": ")
                                #print("**********************empty input, try again********************")
                        else:
                            try: 
                                print(originUser + ": " + decryptedReceivedMsg.decode('utf-8'))
                                user.senderKey = KeyDerivationFunction(user.senderKey, RATCHETING_STEPS)
                            except UnicodeDecodeError:
                                time.sleep(0.5)
                                #print(originUser + ": ")
                                #print("**********************empty input, try again********************")

                    except UnboundLocalError:
                        time.sleep(0.5)

                else:
                    try:
                        decipher = AES.new(user.decryptedKeys[originUser], AES.MODE_EAX,nonce=receivedNonce)
                        decryptedReceivedMsg = decipher.decrypt(receivedMsg)
                        try:
                            decipher.verify(receivedTag)
                        except ValueError:
                            time.sleep(0.5)
                        if originUser != user.id:
                            try:
                                print(originUser + ": " + decryptedReceivedMsg.decode('utf-8'))
                                user.decryptedKeys[originUser] = KeyDerivationFunction(user.decryptedKeys[originUser], RATCHETING_STEPS)
                            except UnicodeDecodeError:
                                time.sleep(0.5)
                                #print(originUser + ": ")
                                #print("**********************empty input, try again********************")
                        else:
                            try: 
                                print(originUser + ": " + decryptedReceivedMsg.decode('utf-8'))
                                user.senderKey = KeyDerivationFunction(user.senderKey, RATCHETING_STEPS)
                            except UnicodeDecodeError:
                                time.sleep(0.5)
                                #print(originUser + ": ")
                                #print("**********************empty input, try again********************")
                    except UnboundLocalError:
                        time.sleep(0.5)

            else:
                print(msg)

def sendThread():
    while True:
        msg = input("> ")
        print ("\033[A                             \033[A")
        if(authenticated and not checkCMD(msg,"#quit")):
            send(msg,client_socket,encrypt=True)
        else:
            send(msg,client_socket)

def on_closing(event=None):
    send("#quit",client_socket)
    client_socket.close()

#HOST = '127.0.0.1'
HOST = 'localhost'
PORT = 65535
if not os.path.exists('data'):
    os.makedirs('data')

BUFSIZ = 4096
ADDR = (HOST, PORT)
HEADER_LENGTH=10

USERNAME_LENGTH=50
RATCHETING_STEPS=5

client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect(ADDR)

receive_thread = Thread(target=receiveThread)
receive_thread.start()

swnd_thread = Thread(target=sendThread)
swnd_thread.start()
