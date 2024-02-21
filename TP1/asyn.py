from ascon import encrypt, decrypt, hash
import asyncio
import os

def emitter(plaintext, key, nonce, associateddata):
    cifra = encrypt(key, nonce, associateddata, plaintext, variant="Ascon-128")
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

# Server
async def handle_echo(reader, writer):
    data = await reader.read(100)
    message = data

    addr = writer.get_extra_info('peername')

    print(f"Received {message} from {addr}")

    recebido = receiver(key, nonce, associateddata, message)

    print(f"Send: {recebido}")
    writer.write(data)
    await writer.drain()

    print("Closing the connection")
    writer.close()

async def main():
    server = await asyncio.start_server(
        handle_echo, '127.0.0.1', 8888)

    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')

    async with server:
        await server.serve_forever()

# Client
async def tcp_echo_client():
    await asyncio.sleep(3)
    reader, writer = await asyncio.open_connection(
        '127.0.0.1', 8888)

    cifra = emitter(plaintext, key, nonce, associateddata)

    print(f'Send: {cifra}')
    writer.write(cifra)

    data = await reader.read(100)
    print(f'Received: {data}')

    print('Closing the connection')
    writer.close()

async def run_client_and_server():
    await asyncio.gather(tcp_echo_client(), main())


plaintext = b"Anacleto manda mensagem a Bernardina"
key, nonce = pseudoRandomGenerator()
associateddata = b"ASCON"

asyncio.run(run_client_and_server())
