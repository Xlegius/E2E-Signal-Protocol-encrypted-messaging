#requires pycryptodome
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util import number
from Crypto.Random.random import randint
from Crypto.Random import get_random_bytes


CIPHER_KEYSIZE = 16 #AES-128

def KeyDerivationFunction(sharedKey,count=1000):
    derivedKey=PBKDF2(str(sharedKey),b"",dkLen=CIPHER_KEYSIZE,count=count)
    return derivedKey

class Server(object):
    def __init__(self,size = 1024):
        print("Choosing a large prime number...")
        self.prime = (number.getPrime(size))
        self.base = 2




class User(object):
    def __init__(self, id, prime, base, isonline=True):
        self.id = id 
        self.p = prime
        self.g = base
        self.privateKey = 0
        self.publicKey = 0
        self.senderKey = None

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
    
    def encryptKey(self, targetUser):
        if(self.senderKey is None):
            self.senderKey = get_random_bytes(CIPHER_KEYSIZE)
        sharedKey = KeyDerivationFunction(self.secretKeys[targetUser])
        cipher = AES.new(sharedKey, AES.MODE_EAX)
        nonce = cipher.nonce
        encryptedKey, tag = cipher.encrypt_and_digest(self.senderKey)
        return(nonce, encryptedKey, tag)

    def encryptKeys(self):
        for targetUser in self.publicKeys:
            self.encryptedKeys[targetUser] = self.encryptKey(targetUser)

    def decryptKey(self, originUser, data):
        sharedKey = KeyDerivationFunction(self.secretKeys[originUser])
        nonce, encryptedKey, tag = data
        cipher = AES.new(sharedKey, AES.MODE_EAX,nonce=nonce)
        decryptedKey=cipher.decrypt(encryptedKey)

        try:
            cipher.verify(tag)
        except ValueError:
            print ("verification failed.")
            return False
        self.decryptedKeys[originUser] = decryptedKey
    
    def decryptKeys (self, encryptedKeys):
        for originUser in encryptedKeys:
            self.decryptKey(originUser, encryptedKeys[originUser])


