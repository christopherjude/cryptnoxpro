from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from Crypto.PublicKey import ECC
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from pathlib import Path
import binascii
import socket
import pickle
import json
import ast
import sys

from tinyec import registry
from Crypto.Cipher import AES
import hashlib, secrets

HEADER = 64
PORT = 5051
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = '!DISCONNECT'
SERVER = '135.181.156.158'
ADDR = (SERVER, PORT)


def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

curve = registry.get_curve('secp256r1')

def encrypt_ECC(msg, pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return (ciphertext, nonce, authTag, ciphertextPubKey)

def decrypt_ECC(encryptedMsg, privKey):
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
    sharedECCKey = privKey * ciphertextPubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext


def send(remote,msg):
    message = msg.encode(FORMAT)
    msg_length = len(message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    remote.send(send_length)
    remote.send(message)


def send_data(remote,data):
    send(remote,'!Data')
    pickled_data = pickle.dumps(data)
    remote.send(pickled_data)


def recv_data(remote):
    pickled_data = remote.recv(1500)
    transaction = pickle.loads(pickled_data)
    return transaction


def remote_tx_check(transaction,public_key):

    transaction['data'] = transaction['data'].decode('ascii')
    digest = SHA256.new(json.dumps(transaction,sort_keys=True).encode(FORMAT))
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),binascii.unhexlify(public_key[1]))
    public_key = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    public_key = ECC.import_key(public_key)
    '''
    <Local> Load private key and sign - sk : server key
    ===================================================
    '''
    with open (f"{Path.home()}/.cryptnoxkeys/sk/private_key.pem", "r") as myfile:
        private_key = ECC.import_key(myfile.read())

    signer = DSS.new(private_key,'fips-186-3')
    sig = signer.sign(digest)

    '''
    <Local> Send to server, await response
    ======================================
    '''
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    client.connect(ADDR)

    enc_tx = str(transaction).encode('utf-8')

    with open(f"{Path.home()}/.cryptnoxkeys/tx/public_key","rb") as file:
        p_pub = file.read()

    encryptedMsg = encrypt_ECC(enc_tx, pickle.loads(p_pub))
    data = {'payload':encryptedMsg,'signature':sig}

    send_data(client,data)
    
    while True:
        try:
            msg_length = client.recv(HEADER).decode(FORMAT)
            if msg_length:
                msg_length = int(msg_length)
                msg = client.recv(msg_length).decode(FORMAT)
                if msg == "!Data":
                    response = recv_data(client)
                    break
        except (KeyboardInterrupt,Exception) as e:
            send(client,DISCONNECT_MESSAGE)
            client.close()
            print(f'Disconnecting {e}')
            break
    if 'error' in response.keys():
        return response['error']
    else:
        '''
        <Card> Check user signature authenticity
        ========================================
        '''
        with open(f"{Path.home()}/.cryptnoxkeys/tx/private_key","rb") as file:
            p_priv = file.read()
        decryptedMsg = decrypt_ECC(response['payload'], pickle.loads(p_priv))
        decoded = ast.literal_eval(decryptedMsg.decode('ascii'))
        
        pubdig = SHA256.new(json.dumps(decoded,sort_keys=True).encode('utf-8'))
        verifier = DSS.new(public_key,'fips-186-3')
        try:
            verifier.verify(pubdig, response['signature'])
            decoded['data'] = decoded['data'].encode('utf-8')
            return decoded
        except Exception as e:
            print(f'Non-authentic user signature')
            return "Non-authentic user signature"
