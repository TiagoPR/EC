from ascon import encrypt, decrypt, hash
import asyncio
import os

async def emitter(message, key, nonce, associateddata):
    cifra = encrypt(key, nonce, associateddata, message, variant="Ascon-128")
    #criptograma = cifra[:-16]
    #tag = cifra[-16:]
    return cifra#, criptograma, tag

async def receiver(key, nonce, associateddata, cifra):
    receivedPlainText = decrypt(key, nonce, associateddata, cifra, variant="Ascon-128")
    if receivedPlainText == None: print("Verification failed :(")
    return receivedPlainText

def pseudoRandomGenerator():
    keySeed = os.urandom(16)
    key = hash(keySeed, variant="Ascon-Xof", hashlength=16)

    nonceSeed = os.urandom(16)
    nonce = hash(nonceSeed, variant="Ascon-Xof", hashlength=16)
    return key, nonce

async def server():
    key, nonce = pseudoRandomGenerator()
    plaintext = b"Anacleto manda mensagem a Bernardina"

    associateddata = b"ASCON"

    cifra = await emitter(plaintext, key, nonce, associateddata)
    print("Mensagem do servidor:", cifra)
    
    await client(key, nonce, associateddata, cifra)


async def client(key, nonce, associateddata, cifra):
    recebido = await receiver(key, nonce, associateddata, cifra)
    print("Cliente recebeu:", recebido.decode())


async def main():
    await asyncio.start_server
    await asyncio.gather(server(), client())

asyncio.run(main())