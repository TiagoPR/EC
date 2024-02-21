from ascon import encrypt, decrypt, hash
import asyncio
import os

def emitter(message, key, nonce, associateddata):
    cifra = encrypt(key, nonce, associateddata, message, variant="Ascon-128")
    #criptograma = cifra[:-16]
    #tag = cifra[-16:]
    return cifra#, criptograma, tag

def receiver(key, nonce, associateddata, cifra):
    receivedPlainText = decrypt(key, nonce, associateddata, cifra, variant="Ascon-128")
    if receivedPlainText == None: print("Verification failed :(")
    return receivedPlainText

def pseudoRandomGenerator():
    keySeed = os.urandom(16)
    key = hash(keySeed, variant="Ascon-Xof", hashlength=16)

    nonceSeed = os.urandom(16)
    nonce = hash(nonceSeed, variant="Ascon-Xof", hashlength=16)
    return key, nonce

key, nonce = pseudoRandomGenerator()
plaintext = b"Anacleto manda mensagem a Bernardina"

associateddata = b"ASCON"

cifra = emitter(plaintext, key, nonce, associateddata)
recebido = receiver(key, nonce, associateddata, cifra)

print(cifra)
print(recebido)

