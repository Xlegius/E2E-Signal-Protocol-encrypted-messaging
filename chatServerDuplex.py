#CMPT471 Project: E2E encrypted messaging system using signal protocol
# Andy Ng and Rahul Anand

#requires pycryptodome
from socket import * # used for creating sockets
from Crypto import * #  PyCryptodome library
import pickle # used for pickling objects (such as dictionaries) into a bytestream so that we can send via socket
from utils import Server # create server object as defined in utils.py
from threading import Thread # used for creating a thread for accepting connections
import time # needed for time.sleep

"""Constants"""
HOST = 'localhost'
PORT = 65535
HEADER_LENGTH = 10
USERNAME_LENGTH=50
ENCODING_TYPE = 'utf-8'
serverConnection = socket(AF_INET, SOCK_STREAM) # AF_INET = IPv4 address, SOCK_STREAM = TCP connection
serverConnection.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1) # SO_REUSEADDR = reuse address immediately after shut down
serverConnection.bind(('', PORT))
serverObject = Server() # object from utils.py (used in encryption)


"""Global variables"""
welcomeMessage= """
***************************************
* Welcome to E2E Encrypted chat.      *
* Enter one of the following commands *
*     - #join                       *
*     - #exit                         *
***************************************
"""
# Dictionary that will store key-value pairs of (username, socket object)
usernameThenSocket={}

# Dictionary that will store key-value pairs of (socket object, username)
#   - can reuse usernameThenSocket, but having socket object as a key in separate dictionary makes it easier to access
socketThenUsername={}

# Store keys needed for encrypted communication between clients
publicKeys={}
encryptedKeys={}
totalClients=0



"""Receive some information from the client such as...
        - client wants to create connection
        - client wants to quit
        - client wants to send message to other client"""
def receivePacket(client, decoded=False):
    header = client.recv(HEADER_LENGTH)
    packet_length = int(header.decode(ENCODING_TYPE).strip()) # strip removes any whitespace

    # Check if message is encoded or not, message such as !join, username, etc. not encoded
    if decoded:
        packet = client.recv(packet_length)
    else:
        packet = client.recv(packet_length).decode(ENCODING_TYPE)

    return packet



"""Send information to clients such as...
        - welcome message
        - if client was created successfully
        - sending keys for encryption"""
def sendPacket(msg, client, encoded=False):
    if not encoded:
       msg = msg.encode(ENCODING_TYPE)
    message_header = f"{len(msg):<{HEADER_LENGTH}}".encode(ENCODING_TYPE)
    client.send(message_header + msg)



"""If a client sends a message, all other connected clients should receive it"""
def sendToAllClients(msg, prefix="", encoded=False):  # prefix is for name identification.
    for socket in socketThenUsername:
        try:
            sendPacket(prefix + msg, socket, encoded)
        except:
            pass



"""Sets up handling for incoming clients."""
def handleNewConnections():
    # Loop forever accepting connections
    while True:
        # socket.accept returns (conn, address)
        #   - conn is a new socket object usable to send and receive data on the connection
        #   - address is the address bound to the socket on the other end of the connection
        client, client_address = serverConnection.accept()
        print(str(client_address) + " wants to create connection")
        connectionsThread = Thread(target = createConnectionWithClient, args = (client,))
        connectionsThread.start()



"""Create connections with clients"""
def createConnectionWithClient(connectionWithClient):
    global totalClients # global variable to keep track of number of clients
    sendPacket(welcomeMessage, connectionWithClient) # send the client the welcome message
    connectionEstablished=False # if the user is successfully connected to chat, tell other users a new user has joined
    connectionAuthenticated=False # the client has an encrypted channel to communicate on

    while True:
        # The client that wants to connect and will enter some command
        encodedCommand=receivePacket(connectionWithClient, decoded=True)
        print("\nMessage received from a client: " + str(encodedCommand))

        # Decode the message using utf-8 encoding
        try:
            command = encodedCommand.decode(ENCODING_TYPE)
        # If error occurs, set the received command to an empty string
        except:
            command = ""

        # If the command received from client is join
        if command == "#join":

            # Prompt the client to enter a username
            sendPacket("Join \nEnter Username : ", connectionWithClient)

            # Receive the message (username) entered by the client
            username = receivePacket(connectionWithClient)

            # Add the clients username, and the socket passed to this function, to our dictionaries
            usernameThenSocket[username]=connectionWithClient
            socketThenUsername[connectionWithClient]=username

            # Send to the client values needed for encryption and notify them
            # Using pickle.dumps to convert the dictionary to a byte-stream, so that we can send it to client via socket
            info={'id':username,'p':serverObject.p, 'g':serverObject.g}
            sendPacket("#join success", connectionWithClient) # inform user if their join is successful
            sendPacket(pickle.dumps(info), connectionWithClient, True)
            totalClients=0

            # Get the new clients public key
            pubKey=receivePacket(connectionWithClient)
            publicKeys[username]=int(pubKey)
            sendToAllClients("#new user")

            # Client has successfully connected to chat, update flag
            connectionEstablished=True

        # If a new client is successfully connected
        elif command == "#new user":
            # Send the public keys to the client
            sendPacket(pickle.dumps(publicKeys), connectionWithClient, encoded=True)

            # Receive key bundle from client
            encryptedKeys[username]=pickle.loads(receivePacket(connectionWithClient, decoded=True))
            totalClients+=1

            # When socket user added to usernameThenSocket, then all the correct keys have been exchanged and calculated
            while totalClients != len(usernameThenSocket):
                time.sleep(1)

            # Get all other keys and send to client, so that client can communicate
            # with all other clients (if more than 2)
            allUsersKeys={}
            for otherUsers in encryptedKeys:
                if otherUsers != username:
                    try: allUsersKeys[otherUsers] = encryptedKeys[otherUsers][username]
                    except: pass
            sendPacket(pickle.dumps(allUsersKeys), connectionWithClient, encoded=True)
            time.sleep(2)

            # If the client has just joined, inform the other clients just once (at the beginning)
            if not connectionAuthenticated:
                sendToAllClients(str(username) + " has joined the chat.", "#broadcast")

            # Encrypted channel established
            connectionAuthenticated=True

        # If the client wants exit chat
        elif command == "#exit":
            user = socketThenUsername[connectionWithClient] # get username of client that wants to exit
            print("Closing connection with client: " + str(user))
            sendPacket("#exit", connectionWithClient) # send message so client program exits
            connectionWithClient.close() # close client socket
            return False # if connection with client closed, close their thread

        # If a client has correctly initialized a connection with the server, every message they send should be sent
        # to all other clients in the chat
        elif connectionEstablished:
            sendToAllClients(encodedCommand, f"{username:<{USERNAME_LENGTH}}".encode(ENCODING_TYPE), encoded=True)



"""Start the server and listen for, and accept connections"""
def main():
    serverConnection.listen(5) # server can listen for up to 5 connections
    print("Listening for connections...")
    connectionThread = Thread(target=handleNewConnections)
    connectionThread.start()
    connectionThread.join()
    serverConnection.close()



"""Call main function"""
if __name__ == "__main__":
    main()


