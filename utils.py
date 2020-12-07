#requires pycryptodome
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util import number
from Crypto.Random.random import randint
from Crypto.Random import get_random_bytes


KEY_SIZE = 16 #AES-128

def KeyDerivationFunction(sharedKey,count=100000):
    salt = b""
    KDF_Key= PBKDF2(str(sharedKey),salt,dkLen=KEY_SIZE,count=count)
    return KDF_Key

class Server(object):
    def __init__(self,size = 1024):
        print("Choosing a large prime number...")
        self.p = (number.getPrime(size))
        self.g = 5

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
        self.makeKeys()

    def makeKeys(self):
        self.privateKey = (randint(1,int(self.p -1)))
        self.publicKey = pow(self.g, self.privateKey, self.p)
    
    def computeSharedKeys(self, pKeys):
        self.publicKeys = pKeys

        for i in self.publicKeys:
            if i not in self.secretKeys:
                if (i == self.id):
                    self.secretKeys[self.id] = 0
                else:
                    self.secretKeys[i] = [pow(self.publicKeys[i], self.privateKey, self.p)]
    
    def encryptKey(self, recvUser):
        if(self.userKey is None):
            self.userKey = get_random_bytes(KEY_SIZE)
        sharedKey = KeyDerivationFunction(self.secretKeys[recvUser])
        cipher = AES.new(sharedKey, AES.MODE_EAX)
        nonce = cipher.nonce
        encryptedKey, tag = cipher.encrypt_and_digest(self.userKey)
        return(nonce, encryptedKey, tag)

    def encryptKeys(self):
        for recvUser in self.publicKeys:
            self.encryptedKeys[recvUser] = self.encryptKey(recvUser)

    def decryptKey(self, sendingUser, data):
        sharedKey = KeyDerivationFunction(self.secretKeys[sendingUser])
        nonce, encryptedKey, tag = data
        cipher = AES.new(sharedKey, AES.MODE_EAX,nonce=nonce)
        decryptedKey= cipher.decrypt(encryptedKey)

        try:
            cipher.verify(tag)
        except ValueError:
            print ("verification failed.")
            return False
        self.decryptedKeys[sendingUser] = decryptedKey
    
    def decryptKeys (self, encryptedKeys):
        for sendingUser in encryptedKeys:
            self.decryptKey(sendingUser, encryptedKeys[sendingUser])


