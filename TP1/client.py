import asyncio
from ascon import encrypt, hash
# import os

def emitter(plaintext, key, nonce, associateddata):
    cifra = encrypt(key, nonce, associateddata, plaintext, variant="Ascon-128")
    #criptograma = cifra[:-16]
    #tag = cifra[-16:]
    return cifra#, criptograma, tag

def pseudoRandomGenerator():
    keySeed = "chave" # os.urandom(16)
    key = hash(keySeed, variant="Ascon-Xof", hashlength=16)

    nonceSeed = "nonce" # os.urandom(16)
    nonce = hash(nonceSeed, variant="Ascon-Xof", hashlength=16)
    return key, nonce

# Client
async def tcp_echo_client():
    reader, writer = await asyncio.open_connection(
        '127.0.0.1', 8888)

    cifra = emitter(plaintext, key, nonce, associateddata)

    print(f'Send: {cifra}')
    writer.write(cifra)

    data = await reader.read(100)
    print(f'Received: {data}')

    print('Closing the connection')
    writer.close()

asyncio.run(tcp_echo_client())