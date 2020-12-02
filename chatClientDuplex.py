from socket import *
import sys
import threading



# If a quit message is received 'q' terminate the threads and close the program
closeConnection = False



"""Sending message to server"""
def send_to_server(clsock):
    global closeConnection # both threads use this global variable

    # Loop forever until a 'q' message is sent or received
    while closeConnection == False:
        
        # Get message from client and send to server
        send_msg = input('\nType Message: ')
        clsock.sendall(send_msg.encode())
        
        # If a quit message is sent, update flag and exit thread
        if send_msg == 'q':
            closeConnection = True
            print('\nClient is closing the connection')

           

"""Receiving message from server""" 
def recv_from_server(conn):
    global closeConnection # both threads use this global variable
    
    # Loop forever until a 'q' message is sent or received
    while closeConnection == False:
        
        # Receives the message from the server
        message = conn.recv(1024).decode()
        
        # If quit message is received from server, update flag and exit thread
        if message == 'q':
            print('\nConnection closed by server')
            conn.close()
            closeConnection = True
        
        # If the message is not empty and not 'q', print it
        if message != False:
           print('\nMessage Received: ' + message)

           

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
    sndThread = threading.Thread(target = send_to_server, args = (clientSocket,))
    
    # Create a TCP socket, and a thread for receiving messages
    receivingSocket = socket(AF_INET, SOCK_STREAM)
    receivingSocket.bind(('', clientPort))
    receivingSocket.listen(1)
    clientconnection, addr = receivingSocket.accept()
    print('Client connection with server established')
    print('Send \"q\" to close connection and quit program')
    rcvThread = threading.Thread(target = recv_from_server, args = (clientconnection,))
    
    # Start the sending and receiving threads
    # Setting a daemons so that threads are killed when main program exits
    sndThread.daemon = True
    rcvThread.daemon = True
    sndThread.start()
    rcvThread.start()
    
    # Close the program when a quit message is sent or recieved
    while(closeConnection == False):
        if(closeConnection == True):
            print('Program finished')
            sys.exit()




"""Execute main function"""
if __name__ == '__main__':
    main()


