#CMPT471 Project: E2E encrypted messaging system using signal protocol
# Andy Ng and Rahul Anand

#requires pycryptodome
from socket import * # used for creating sockets
from Crypto import * #  PyCryptodome library
import pickle # used for pickling objects (such as dictionaries) into a bytestream so that we can send via socket
from tools import Server # create server object as defined in utils.py
from threading import Thread # used for creating a thread for accepting connections
import time # needed for time.sleep

"""Constants and global variables"""
HOST = 'localhost'
PORT = 65535
headerSize = 10
usernameSize=50
encodingType = 'utf-8'
serverConnection = socket(AF_INET, SOCK_STREAM) # AF_INET = IPv4 address, SOCK_STREAM = TCP connection
serverConnection.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1) # SO_REUSEADDR = reuse address immediately after shut down
serverConnection.bind(('', PORT))
serverObject = Server() # object from utils.py (used in encryption)

# Store keys needed for encrypted communication between clients
publicKeys={}
encryptedKeys={}
totalClients=0
# Dictionary that will store key-value pairs of (username, socket object)
usernames_dict={}
# Dictionary that will store key-value pairs of (socket object, username)
#   - can reuse usernames_dict, but having socket object as a key in separate dictionary makes it easier to access
sockets_dict={}


welcomeMessage= """
*******************************************************
*        Welcome to E2E Encrypted chat.               *
*                                                     *
*   - To enter chatroom, enter #join                  *
*   - When in chatroom, enter #exit to exit           *
*******************************************************
"""


"""Start the server and listen for, and accept connections"""
def main():
    serverConnection.listen(5) # server can listen for up to 5 connections
    print("Listening for connections...")
    connection = Thread(target=handleNewConnections)
    connection.start()
    connection.join()
    serverConnection.close()


"""Manage connection with client"""
def connectionThread(connectionWithClient):
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
            command = encodedCommand.decode(encodingType)
        # If error occurs, set the received command to an empty string
        except:
            command = ""

        # If the command received from client is join
        if command == "#join":

            # Prompt the client to enter a username
            sendPacket("Join \nEnter Username : ", connectionWithClient)

            # Receive the message (username) entered by the client
            username = receivePacket(connectionWithClient)

            if username in usernames_dict:
                    sendPacket("User is currently active from a different device. \nPlease quit with Ctrl+C and try again",connectionWithClient)
                    Thread(target = connectionAuthenticated,args=(connectionWithClient,)).start()
                    return False

            # Add the clients username, and the socket passed to this function, to our dictionaries
            usernames_dict[username]=connectionWithClient
            sockets_dict[connectionWithClient]=username

            # Send to the client values needed for encryption and notify them
            # Using pickle.dumps to convert the dictionary to a byte-stream, so that we can send it to client via socket
            info={'id':username,'p':serverObject.p, 'g':serverObject.g}
            sendPacket("#join success", connectionWithClient) # inform user if their join is successful
            sendPacket(pickle.dumps(info), connectionWithClient, True)
            totalClients=0

            # Get the new clients public key and send to all other clients
            pubKey=receivePacket(connectionWithClient)
            publicKeys[username]=int(pubKey)
            for socket in sockets_dict:
                sendPacket("#new user", socket)

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
            while totalClients != len(usernames_dict):
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
                for socket in sockets_dict:
                    message = "#notice" + "--- " + str(username) + " has joined the chat. ---\n"
                    sendPacket(message, socket)

            # Encrypted channel established
            connectionAuthenticated=True

        # If the client wants exit chat
        elif command == "#exit":
            user = sockets_dict[connectionWithClient] # get username of client that wants to exit
            print("Closing connection with client: " + str(user))
            sendPacket("#exit", connectionWithClient) # send message so client program exits

            for socket in sockets_dict:
                    message = "#notice" + "--- " + str(user) + " has exited the chat. ---"
                    sendPacket(message, socket)

            del sockets_dict[connectionWithClient]
            del usernames_dict[user]
            connectionWithClient.close() # close client socket
            return False # if connection with client closed, close their thread

        # If a client has correctly initialized a connection with the server, every message they send should be sent
        # to all other clients in the chat
        elif connectionEstablished:
            message = f"{username:<{usernameSize}}".encode(encodingType) + encodedCommand
            for socket in sockets_dict:
                sendPacket(message, socket, encoded = True)


"""Receive some information from the client such as...
        - client wants to create connection
        - client wants to quit
        - client wants to send message to other client"""
def receivePacket(client, decoded=False):
    header = client.recv(headerSize)
    packet_length = int(header.decode(encodingType).strip()) # strip removes any whitespace

    # Check if message is encoded or not, message such as !join, username, etc. not encoded
    if decoded:
        packet = client.recv(packet_length)
    else:
        packet = client.recv(packet_length).decode(encodingType)

    return packet


"""Send information to clients such as...
        - welcome message
        - if client was created successfully
        - sending keys for encryption"""
def sendPacket(msg, client, encoded=False):
    if not encoded:
       msg = msg.encode(encodingType)
    message_header = f"{len(msg):<{headerSize}}".encode(encodingType)
    client.send(message_header + msg)


"""Set up for accepting a new client connection."""
def handleNewConnections():
    # Loop forever accepting connections
    while True:
        # socket.accept returns (conn, address)
        #   - conn is a new socket object usable to send and receive data on the connection
        #   - address is the address bound to the socket on the other end of the connection
        client, client_address = serverConnection.accept()
        print(str(client_address) + " wants to create connection")
        newConnection = Thread(target = connectionThread, args = (client,))
        newConnection.start()


"""Call main function"""
if __name__ == "__main__":
    main()

