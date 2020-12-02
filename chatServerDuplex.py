from socket import *
import sys
import threading



# If a quit message is received 'q' terminate the threads and close the program
closeConnection = False



"""Receiving message from client"""
def recv_from_client(clsock):
    global closeConnection # both threads use this global variable

    # Loop forver, terminate if a quit ("q") message is received
    while closeConnection == False:
        data = clsock.recv(1024).decode()
        
        # If server receives a "q", close the connection
        if data == 'q':
            print('\Connection closed by client')
            closeConnection = True
        
        # If the data is not a "q" and is not empty, print the message
        if data != False:
           print('\nMessage Received: ', data)
        
        

"""Sending message to client"""
def send_to_client(conn):
    global closeConnection # both threads use this global variable

    # Loop forver, terminate if a quit ("q") message is sent
    while closeConnection == False:
        try:
            # Input a message
            send_msg = input('\nType Message: ')
            
            # If the message is "q", close the connection after sending the message
            if send_msg == 'q':
                conn.send(send_msg.encode())
                print('\nServer is closing connection')
                conn.close()
                closeConnection = True
            else:
                conn.send(send_msg.encode())
        
        # If an error occurs, close the connection
        except:
            conn.close()
    


"""Main Function"""
def main():
    global closeConnection # both threads use this global variable

    # Define host and ports
    HOST = 'localhost'
    listeningPort = 65535   # listening for connections
    clientPort = 65534      # port of client
    
    # Creating a TCP socket to listen for connections
    #   - AF_INET for IPv4 addresses
    #   - SOCK_STREAM for TCP connections
    listeningSocket = socket(AF_INET, SOCK_STREAM)
    
    # Bind the listening socket to the port
    listeningSocket.bind(('', listeningPort))
    
    # Listen for at most 1 connection
    listeningSocket.listen(1) 
    print('Server is listening for incoming connections')
    
    # Accept a connection request from the client
    connectionSocket, addr = listeningSocket.accept()
    print('Server has connected with a client')
    print('Send \"q\" to close connection and quit program')

    # Creating a TCP socket for sending messages
    sendingSocket = socket(AF_INET, SOCK_STREAM)
    sendingSocket.connect((HOST, clientPort))
    
    # Create two threads, one for receiving messages and one for sending messages
    #   - two seperate threads so that we can send and receive messages at the same time
    rcvThread = threading.Thread(target = recv_from_client, args = (connectionSocket,))
    sndThread = threading.Thread(target = send_to_client, args = (sendingSocket,))
    
    # Start the sending and receiving threads
    # Setting a daemons so that threads are killed when main program exits
    sndThread.daemon = True
    rcvThread.daemon = True
    rcvThread.start()
    sndThread.start()
    
    # Close the program when a quit message is sent or recieved
    while(closeConnection == False):
        if(closeConnection == True):
            print('Program finished')
            sys.exit()



"""Execute main function"""
if __name__ == '__main__':
    main()


