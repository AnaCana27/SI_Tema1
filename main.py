from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from hashlib import md5
from base64 import b64decode
from base64 import b64encode
from Cryptodome.Util.Padding import pad, unpad
import threading
import math

msg = "ana are mere si pere si banana si struguri si iaurt dljsofisjnjfnjnsflneknfs cknecslojcoem.  wkdjoiejdnesd aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
k1 = "aaaabbbbccccdddd"
k2 = "aaabbbcccdddeeee"
keyMaster = "abcdefghijklmnop"
descriptor = []  # ce transmitem intre thread-uri
identifier = [0]  # pt thread ul curent
lock = threading.Lock()
print("master_key...: ", keyMaster)
print("k1 ECB...: ", k1)
print("k2 CBC...: ", k2)
print(msg)

block_size = 16  # Bytes
padd = lambda s: s + (block_size - len(s) % block_size) * \
                 chr(block_size - len(s) % block_size)
unpadd = lambda s: s[:-ord(s[len(s) - 1:])]


def message_to_blocks(x, size):
    n_blocks = math.ceil(len(x) / size)
    return [x[size * i:size * (i + 1)] for i in range(n_blocks)]


class AES_ECB_Cipher:
    def __init__(self, key):
        self.key = md5(key.encode('utf8')).hexdigest() # encode produce un hash de 128 bits si hexdigets returneaza un hex string care reprezinta acel hash

    # def encrypt(self, raw):
    #     blocks_encrypted = []
    #     blocks = [padd(x) for x in message_to_blocks(raw, 16)]
    #     for block in blocks:
    #         cipher = AES.new(self.key.encode("utf8"), AES.MODE_ECB)
    #         blocks_encrypted.append(b64encode(cipher.encrypt(block.encode('utf8'))))
    #     blocks_encrypted = b''.join(blocks_encrypted)
    #     return blocks_encrypted

    def encrypt(self, raw):
        raw = padd(raw)
        cipher = AES.new(self.key.encode("utf8"), AES.MODE_ECB) # new creaza un nou sir aes
        return b64encode(cipher.encrypt(raw.encode('utf8'))) # b64encode conversie bytes la ASCII

    # def decrypt(self, enc):
    #     blocks_decrypted = []
    #     enc = b64decode(enc)
    #     blocks = [x for x in message_to_blocks(enc, 16)]
    #     for block in blocks:
    #         cipher = AES.new(self.key.encode("utf8"), AES.MODE_ECB)
    #         blocks_decrypted.append((cipher.decrypt(block)).decode('utf8'))
    #     blocks_decrypted = ''.join(blocks_decrypted)
    #     return blocks_decrypted

    def decrypt(self, enc):
        enc = b64decode(enc)
        cipher = AES.new(self.key.encode("utf8"), AES.MODE_ECB)
        return unpadd(cipher.decrypt(enc)).decode('utf8')


text_ecb = AES_ECB_Cipher(k1).encrypt(msg)

print('Message crypted ECB...:', text_ecb)
print("Message decrypted ECB...: ", AES_ECB_Cipher(k1).decrypt(text_ecb))


class AES_CBC_Cipher:
    def __init__(self, key):
        self.key = md5(key.encode('utf8')).digest()

    # def encrypt(self, data):
    #     blocks_encrypted = []
    #     blocks = [padd(x) for x in message_to_blocks(data, 16)]
    #     for block in blocks:
    #         iv = get_random_bytes(AES.block_size)
    #         self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
    #         blocks_encrypted.append(b64encode(iv + self.cipher.encrypt(pad(block.encode('utf-8'),
    #                                                                        AES.block_size))))
    #     blocks_encrypted = b''.join(blocks_encrypted)
    #     return blocks_encrypted

    def encrypt(self, data):
        iv = get_random_bytes(AES.block_size)
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + self.cipher.encrypt(pad(data.encode('utf-8'),
                                                      AES.block_size)))

    # def decrypt(self, data):
    #     blocks_decrypted = []
    #     raw = b64decode(data)
    #     blocks = [x for x in message_to_blocks(data, 16)]
    #     for block in blocks:
    #         self.cipher = AES.new(self.key, AES.MODE_CBC, raw[:AES.block_size])
    #         blocks_decrypted.append(unpad(self.cipher.decrypt(raw[AES.block_size:]), AES.block_size))
    #     blocks_decrypted =b''.join(blocks_decrypted)
    #     return blocks_decrypted

    def decrypt(self, data):
        raw = b64decode(data)
        self.cipher = AES.new(self.key, AES.MODE_CBC, raw[:AES.block_size])
        return unpad(self.cipher.decrypt(raw[AES.block_size:]), AES.block_size)


text_cbc = AES_CBC_Cipher(k2).encrypt(msg).decode('utf-8')
print('Message crypted CBC...: ', text_cbc)
print('Message decrypted CBC...:', AES_CBC_Cipher(k2).decrypt(text_cbc).decode('utf-8'))


class nod_MC():
    def __init__(self, key1, key2, master_key, *args, **kwargs):
        super(nod_MC, self).__init__(*args, **kwargs)
        self.k1 = k1
        self.k2 = k2
        self.master_key = master_key

    # cripteaza cheile k1 k2 cu ECB si master key
    def get_k1(self):
        return AES_ECB_Cipher(self.master_key).encrypt(self.k1)

    def get_k2(self):
        return AES_ECB_Cipher(self.master_key).encrypt(self.k2)


class nod_A(threading.Thread):
    def __init__(self, encryption_mode, mc_nod, master_key, message, descriptor, identifier, lock, *args, **kwargs):
        super(nod_A, self).__init__(*args, **kwargs)
        self.encryption_mode = encryption_mode
        self.master_key = master_key
        self.message = message
        self.mc_nod = mc_nod
        self.descriptor = descriptor
        self.identifier = identifier
        self.lock = lock

    def run(self):
        # decripteaza cheile venite de la MC
        while True:
            # acquire() lets us acquire a blocking or non-blocking lock.
            # When locked, an RLock belongs to a certain thread; but when unlocked, no thread owns it.
            self.lock.acquire()
            if self.identifier.pop(0) == 0:
                self.identifier.append(1)
                if self.encryption_mode == 'ecb':
                    key1 = AES_ECB_Cipher(self.master_key).decrypt(self.mc_nod.get_k1())
                elif self.encryption_mode == 'cbc':
                    key2 = AES_CBC_Cipher(self.master_key).decrypt(self.mc_nod.get_k2())
                self.descriptor.append(self.encryption_mode)
                # This method releases a lock. This means no thread owns it. If other threads are blocked, only one of them may continue
                # When this method is called, one out of the already waiting threads to acquire the lock is allowed to hold the lock.
                self.lock.release()
                break
            if len(self.identifier) == 0:
                self.identifier.append(1)
            self.lock.release()

        # receives permission from B
        while True:
            self.lock.acquire()
            if self.identifier.pop(0) == 0:
                self.descriptor.pop(0)
                self.identifier.append(0)
                self.lock.release()
                break
            if len(self.identifier) == 0:
                self.identifier.append(1)
            self.lock.release()

        blocks = [padd(x) for x in message_to_blocks(self.message, 16)]

        # A cripteaza mesajul pe care vrea sa-l trimita la B
        while True:
            self.lock.acquire()
            if self.identifier.pop(0) == 0:
                if self.encryption_mode == "ecb":
                    descriptor.append(AES_ECB_Cipher(key1).encrypt(self.message))
                else:
                    encryptedMessage = AES_CBC_Cipher(key2).encrypt(self.message)
                    descriptor.append(encryptedMessage)
                self.identifier.append(1)
                self.lock.release()
                break
            if len(self.identifier) == 0:
                self.identifier.append(1)
            self.lock.release()


class nod_B(threading.Thread):
    def __init__(self, master_key, mc_nod, descriptor, identifier, lock, *args, **kwargs):
        super(nod_B, self).__init__(*args, **kwargs)
        self.master_key = master_key
        self.mc_nod = mc_nod
        self.descriptor = descriptor
        self.identifier = identifier
        self.lock = lock

    def run(self):
        # decripteaza cheile venite de la MC
        while True:
            self.lock.acquire()
            if self.identifier.pop(0) == 1:
                self.identifier.append(1)
                if self.descriptor[0] == 'ecb':
                    mode_cript = 'ecb'
                    key1 = AES_ECB_Cipher(self.master_key).decrypt(self.mc_nod.get_k1())
                elif self.descriptor[0] == 'cbc':
                    mode_cript = "cbc"
                    key2 = AES_ECB_Cipher(self.master_key).decrypt(self.mc_nod.get_k2())
                self.descriptor.pop(0)
                self.lock.release()
                break
            if len(self.identifier) == 0:
                self.identifier.append(0)
            self.lock.release()

        # i'm ready message sent to A
        while True:
            self.lock.acquire()
            if self.identifier.pop(0) == 1:
                self.descriptor.append("i'm ready")
                self.identifier.append(0)
                self.lock.release()
                break
            if len(self.identifier) == 0:
                self.identifier.append(0)
            self.lock.release()

        response = ""

        while True:
            self.lock.acquire()
            if self.identifier.pop(0) == 1:
                self.identifier.append(0)
                if mode_cript == 'ecb':
                    while not (len(self.descriptor) == 0):
                        block = self.descriptor.pop(0)
                        decrypted = AES_ECB_Cipher(key1).decrypt(block)
                        response += unpadd(decrypted).decode('utf-8')
                else:
                    fromlist = descriptor.pop(0)
                    result = AES_CBC_Cipher(key2).decrypt(fromlist)
                self.lock.release()
                break
            if len(self.identifier) == 0:
                self.identifier.append(0)
            self.lock.release()

        print(response)


MC = nod_MC(
    key1=k1,
    key2=k2,
    master_key=keyMaster
)

A = nod_A(
    encryption_mode='ebc',
    master_key=keyMaster,
    message=msg,
    mc_nod=MC,
    descriptor=descriptor,
    identifier=identifier,
    lock=lock
)

B = nod_B(
    master_key=keyMaster,
    mc_nod=MC,
    descriptor=descriptor,
    identifier=identifier,
    lock=lock

)

A.start()
B.start()

A.join()
B.join()
