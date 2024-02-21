import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

data = b"a secret message"

aad = b"authenticated but unencrypted data"

key = ChaCha20Poly1305.generate_key()

chacha = ChaCha20Poly1305(key)

tweak = os.urandom(12)

ct = chacha.encrypt(tweak, data, aad)

original = chacha.decrypt(tweak, ct, aad)
print(original)