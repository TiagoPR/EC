import os
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Geração das chaves privadas X448 e Ed448
x448_private_key = X448PrivateKey.generate()
ed448_private_key = Ed448PrivateKey.generate()

# Geração das chaves públicas X448 e Ed448
x448_public_key = x448_private_key.public_key()
ed448_public_key = ed448_private_key.public_key()

# Acordo de chaves com X448
shared_key = x448_private_key.exchange(x448_public_key)

# Assinatura da chave compartilhada com Ed448
signature = ed448_private_key.sign(shared_key)

# Verificação da assinatura com Ed448
try:
    ed448_public_key.verify(signature, shared_key)
    print("A assinatura é válida.")
except:
    print("A assinatura é inválida.")

# Criação do canal privado de informação com ChaCha20Poly1305
chacha = ChaCha20Poly1305(shared_key)

# Dados a serem criptografados
data = b"mensagem secreta"

# Dados associados
aad = b"dados associados"

# Criptografar os dados
nonce = os.urandom(12)  # 96 bits
ct = chacha.encrypt(nonce, data, aad)

# Descriptografar os dados
pt = chacha.decrypt(nonce, ct, aad)

print("Texto plano:", pt)