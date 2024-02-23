from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.algorithms import AES256
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import asyncio
import os

def emitter(plaintext, key, nonce, associateddata):
    # Cifrar os dados
    cifra = chacha.encrypt(nonce, plaintext, associateddata)
    return cifra

def receiver(key, nonce, associateddata, cifra):
    # Decifrar os dados
    receivedPlainText = chacha.decrypt(nonce, cifra, associateddata)
    if receivedPlainText == None: print("Verification failed :(")
    return receivedPlainText

def pseudoRandomGenerator():
    # Geração das chaves privadas X448 e Ed448
    x448_private_key = X448PrivateKey.generate()
    ed448_private_key = Ed448PrivateKey.generate()

    # Geração das chaves públicas X448 e Ed448
    x448_public_key = x448_private_key.public_key()
    ed448_public_key = ed448_private_key.public_key()

    # Acordo de chaves com X448
    shared_key = x448_private_key.exchange(x448_public_key)

    # Perform key derivation.
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)

    # Assinatura da chave compartilhada com Ed448
    signature = ed448_private_key.sign(derived_key)

    # Verificação da assinatura com Ed448
    try:
        ed448_public_key.verify(signature, derived_key)
        print("A assinatura é válida.")
    except:
        print("A assinatura é inválida.")

    # Criptografar os dados
    nonce = os.urandom(12)  # 96 bits
    return derived_key, nonce

# Server
async def handle_echo(reader, writer):
    data = await reader.read(100)
    message = data

    addr = writer.get_extra_info('peername')

    print(f"Server has received {message} from client {addr}")

    print("Decrypting...")
    data = receiver(key, nonce, associateddata, message)

    print(f"Server has sent: {data}")
    writer.write(data)
    await writer.drain()

    print("Closing the server connection")
    writer.close()
    

async def main():
    server = await asyncio.start_server(
        handle_echo, '127.0.0.1', 8889)

    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')

# Client
async def tcp_echo_client():
    await asyncio.sleep(3)
    reader, writer = await asyncio.open_connection(
        '127.0.0.1', 8889)
    
    print("Sending: ", plaintext)

    print('Encrypting...')
    cifra = emitter(plaintext, key, nonce, associateddata)

    print(f'Client has sent: {cifra}')
    writer.write(cifra)

    data = await reader.read(100)
    print(f'Client has received: {data}')

    print('Closing the client connection')
    writer.close()

async def run_client_and_server():
    await asyncio.gather(tcp_echo_client(), main())


plaintext = b"Anacleto manda mensagem a Bernardina"
key, nonce = pseudoRandomGenerator()
chacha = ChaCha20Poly1305(key)
associateddata = b"ASCON"

asyncio.run(run_client_and_server())