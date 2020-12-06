from socket import *
import sys
import threading


# If a quit message is received 'q' terminate the threads and close the program
closeConnection = False

# Diffie-hellman variables
sharedPrime = 0
sharedBase = 0
serverValue = 0
secret = 0
sharedSecret = 0



"""Perform diffie hellman key exchange"""
def diffie_hellman(snd_conn, rcv_conn): 
    global sharedPrime, sharedBase, serverValue, secret, sharedSecret
    
    print('\n\n--------------------Performing Diffie Hellman--------------------')
    
    # Client should receive 3 numbers from server
    #   - sharedPrime 
    #   - sharedBase
    #   - a server calculated number based on the shared and secret keys
    recvVals = 0
    
    # Get the prime modulus and generator from server 
    while recvVals < 3:
        
        # Receives the message from the server
        message = rcv_conn.recv(1024).decode()
        
        # If the message is not empty and not 'q', print it
        if message != False:
            if recvVals == 0:
                print('Shared Prime received: ' + message)
                sharedPrime = int(message)
            elif recvVals == 1:
                print('Shared base received: ' + message)
                sharedBase = int(message)
            elif recvVals == 2:
                print('Server calculated value received: ' + message)
                serverValue = int(message)
            recvVals+=1
         
    # Calculate the value based on the shared and secret keys, and send it to client
    secret = 15
    clientValue = str((sharedBase ** secret) % sharedPrime)
    print('Client sending calculated value: ' + clientValue)
    snd_conn.sendall(clientValue.encode())
    
    # Calculate shared secret
    sharedSecret = (serverValue**secret) % sharedPrime
    print('Client Shared Secret calculated: ' + str(sharedSecret))

        
    






"""Sending message to server"""
def send_to_server(snd_conn):
    global closeConnection # both threads use this global variable

    # Loop forever until a 'q' message is sent or received
    while closeConnection == False:
        
        # Get message from client and send to server
        send_msg = input('\nType Message: ')
        snd_conn.sendall(send_msg.encode())
        
        # If a quit message is sent, update flag and exit thread
        if send_msg == 'q':
            closeConnection = True
            print('\nClient is closing the connection')

           

"""Receiving message from server""" 
def recv_from_server(rcv_conn):
    global closeConnection # both threads use this global variable
    
    # Loop forever until a 'q' message is sent or received
    while closeConnection == False:
        
        # Receives the message from the server
        message = rcv_conn.recv(1024).decode()
        
        # If the message is not empty and not 'q', print it
        if message != False:
           print('\nMessage Received: ' + message)
        
        # If quit message is received from server, update flag and exit thread
        if message == 'q':
            print('\nConnection closed by server')
            closeConnection = True
        

   
"""Main function"""
def main():
    global closeConnection
    
    # Define host and ports
    HOST = 'localhost'
    serverPort = 65535
    clientPort = 65534
    
    # Create a TCP client socket and a thread for sending messages
    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.connect((HOST, serverPort))
    
    # Create a TCP socket, and a thread for receiving messages
    receivingSocket = socket(AF_INET, SOCK_STREAM)
    receivingSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1) # can reuse address immediately after shutting down
    receivingSocket.bind(('', clientPort))
    receivingSocket.listen(1)
    clientconnection, addr = receivingSocket.accept()
    print('-----------------------------------------------')
    print('Client connection with server established')
    print('Send \"q\" to close connection and quit program')
    print('-----------------------------------------------')
    rcvThread = threading.Thread(target = recv_from_server, args = (clientconnection,))
    
    
    
    
    # Perform diffie-hellman key exchange
    diffie_hellman(clientSocket, clientconnection)
    
    
    
    
    
    
    # Create two threads, one for receiving messages and one for sending messages
    #   - two seperate threads so that we can send and receive messages at the same time
    #rcvThread = threading.Thread(target = recv_from_server, args = (clientconnection,))
    #sndThread = threading.Thread(target = send_to_server, args = (clientSocket,))

    
    
    # Start the sending and receiving threads
    # Setting a daemons so that threads are killed when main program exits
    #sndThread.daemon = True
    #rcvThread.daemon = True
    #sndThread.start()
    #rcvThread.start()
    
    # Close the program when a quit message is sent or recieved
    #while(closeConnection == False):
    #    if(closeConnection == True):
    #        print('Program finished')
    #        sys.exit()


"""Execute main function"""
if __name__ == '__main__':
    main()


