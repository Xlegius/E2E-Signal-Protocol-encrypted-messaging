#CMPT471 Project: E2E encrypted messaging system using signal protocol
# Andy Ng and Rahul Anand

#requires pycryptodome
from Crypto.Cipher import AES           #for encryption
from Crypto.Protocol.KDF import PBKDF2  
from Crypto.Util import number
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint

"""constants"""
KEY_SIZE = 16 #Using AES-128

#Using PBKDF2 to do Key Derivation on a shared key from https://pycryptodome.readthedocs.io/en/latest/src/protocol/kdf.html
def KeyDerivation(sharedKey,count=100000):
    salt = b""
    KD_Key= PBKDF2(str(sharedKey),salt,dkLen=KEY_SIZE,count=count)
    return KD_Key

class Server(object):
    def __init__(self,size = 1024):
        print("Choosing a large prime number p...")
        self.p = (number.getPrime(size))
        print("Choosing a large prime number g...")
        self.g = (number.getPrime(size))

class User(object):
    def __init__(self, id, prime, base, isonline=True):
        self.id = id 
        self.p = prime
        self.g = base
        self.privateKey = 0
        self.publicKey = 0
        self.userKey = None

        self.secretKeys = {}
        self.publicKeys = {}
        self.encryptedKeys = {}
        self.decryptedKeys = {}

    """ initializing keys for Diffie-Hellman Key exchange"""
    def makeKeys(self):
        self.privateKey = (randint(1,int(self.p -1)))
        self.publicKey = pow(self.g, self.privateKey, self.p)               #g^private key mod p
    
    """Computes the secret DH key"""
    def computeSharedKeys(self, pKeys):
        self.publicKeys = pKeys

        for i in self.publicKeys:
            if i not in self.secretKeys:
                if (i == self.id):
                    self.secretKeys[self.id] = 0
                else:
                    self.secretKeys[i] = [pow(self.publicKeys[i], self.privateKey, self.p)]     #publickey ^privatekey mod p

    """encrypt specific userKey"""
    def encryptKey(self, recvUser):
        #create a userkey if it does not exist
        if(self.userKey is None):
            self.userKey = get_random_bytes(KEY_SIZE)
        
        #Generate a shared key using Key Derivation 
        sharedKey = KeyDerivation(self.secretKeys[recvUser])

        #AES, standard example from https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html?highlight=AES
        cipher = AES.new(sharedKey, AES.MODE_EAX)
        nonce = cipher.nonce
        encryptedKey, tag = cipher.encrypt_and_digest(self.userKey)
        return(nonce, encryptedKey, tag)

    """encrypt all keys"""
    def encryptKeys(self):
        for recvUser in self.publicKeys:
            self.encryptedKeys[recvUser] = self.encryptKey(recvUser)

    """decrypt specific userKey"""
    def decryptKey(self, sendingUser, data):
        #Generate a shared key from the secret key using Key Derivation 
        sharedKey = KeyDerivation(self.secretKeys[sendingUser])

        #AES, standard example from https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html?highlight=AES
        nonce, encryptedKey, tag = data
        cipher = AES.new(sharedKey, AES.MODE_EAX,nonce=nonce)
        decryptedKey= cipher.decrypt(encryptedKey)

        #to make sure the data is not faulty
        try:
            cipher.verify(tag)
        except ValueError:
            print ("verification failed.")
            return False
        self.decryptedKeys[sendingUser] = decryptedKey
    
    """decrypt all keys"""
    def decryptKeys (self, encryptedKeys):
        for sendingUser in encryptedKeys:
            self.decryptKey(sendingUser, encryptedKeys[sendingUser])


