from socket import *
import sys
import threading
import time
import sympy # Library for generating prime numbers

# If a quit message is received 'q' terminate the threads and close the program
closeConnection = False



"""Generate random prime number to use in diffie hellman"""
def generate_random_prime():
    lowerBound = 100
    upperBound = 999
    primes = [i for i in range(lowerBound,upperBound) if isPrime(i)]
    n = random.choice(primes)
    return n



"""Perform diffie hellman key exchange"""
def diffie_hellman(snd_conn, rcv_conn):

    print('\n\n--------------------Performing Diffie Hellman--------------------')
    # Generate the values
    prime = 23
    base = 5
    secret = 6
    sendToClient = (base**secret) % prime
    sharedPrime = str(23)
    sharedBase = str(5)
    sharedValue = str(sendToClient)
    valueFromClient = 0
    serverSharedSecret = 0
    
    # Send the values
    print('Sending randomly generated shared prime to client: ' + sharedPrime)
    print('Sending randomly generated shared base to client: '  + sharedBase)
    print('Sending calculated value to client: ' + sharedValue)
    snd_conn.send(sharedPrime.encode())
    time.sleep(1)
    snd_conn.send(sharedBase.encode())
    time.sleep(1)
    snd_conn.send(sharedValue.encode())
    
    # Get the calculated value from the client
    while True:
        valueFromClient = int(rcv_conn.recv(1024).decode())
        break
    print('Calculated value received from client: ' + str(valueFromClient))
    
    # Calculate the shared secret
    serverSharedSecret = (valueFromClient ** secret) % int(sharedPrime)
    print('\nServer Shared Secret calculated: ' + str(serverSharedSecret))
    print('------------------------------------------------------------------')



   
    



"""Receiving message from client"""
def recv_from_client(rcv_conn):
    global closeConnection # both threads use this global variable

    # Loop forver, terminate if a quit ("q") message is received
    while closeConnection == False:
        data = rcv_conn.recv(1024).decode()
        
        # If server receives a "q", close the connection
        if data == 'q':
            print('\nConnection closed by client')
            closeConnection = True
        
        # If the data is not a "q" and is not empty, print the message
        if data != False:
           print('\nMessage Received: ', data)
        
        

"""Sending message to client"""
def send_to_client(snd_conn):
    global closeConnection # both threads use this global variable

    # Loop forver, terminate if a quit ("q") message is sent
    while closeConnection == False:
        # Input a message
        send_msg = input('\nType Message: ')
            
        # If the message is "q", close the connection after sending the message
        if send_msg == 'q':
            snd_conn.send(send_msg.encode())
            print('\nServer is closing connection')
            closeConnection = True
        else:
            snd_conn.send(send_msg.encode())
        


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
    listeningSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1) # can reuse address immediately after shutting down
    listeningSocket.bind(('', listeningPort))
    
    # Listen for at most 1 connection
    listeningSocket.listen(1) 
    print('--------------------------------------------')
    print('Server is listening for incoming connections')
    
    # Accept a connection request from the client
    connectionSocket, addr = listeningSocket.accept()
    print('Server has connected with a client')
    print('Send \"q\" to close connection and quit program')
    print('--------------------------------------------')

    # Creating a TCP socket for sending messages
    sendingSocket = socket(AF_INET, SOCK_STREAM)
    sendingSocket.connect((HOST, clientPort))
    
    
    
    
    # Perform diffie-hellman key exchange before sending messages
    diffie_hellman(sendingSocket, connectionSocket)
    
    
    
    
    # Create two threads, one for receiving messages and one for sending messages
    #   - two seperate threads so that we can send and receive messages at the same time
    #rcvThread = threading.Thread(target = recv_from_client, args = (connectionSocket,))
    #sndThread = threading.Thread(target = send_to_client, args = (sendingSocket,))
    
    # Start the sending and receiving threads
    # Setting a daemons so that threads are killed when main program exits
    #sndThread.daemon = True
    #rcvThread.daemon = True
    #rcvThread.start()
    #sndThread.start()
    
    # Close the program when a quit message is sent or recieved
    #while(closeConnection == False):
    #    if(closeConnection == True):
    #        print('Program finished')
    #        sys.exit()



"""Execute main function"""
if __name__ == '__main__':
    main()


