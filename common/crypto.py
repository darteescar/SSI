"""
crypto.py — Módulo central de primitivas criptográficas
========================================================
Todas as operações criptográficas do projeto passam por aqui.
Nunca duplicar lógica crypto fora deste ficheiro.

Grupos de funcionalidade (por ordem de dependência):
  1. PBKDF2          — hash de passwords
  2. AES-GCM         — cifra autenticada (canal + E2EE)
  3. RSA             — geração, serialização, OAEP, PSS
  4. Cifra híbrida   — RSA + AES-GCM (registo)
  5. ChaCha20-Poly1305 — cifra autenticada de ficheiros locais
  6. DH              — acordo de chaves
  7. HKDF            — derivação de session_key e rotação
  8. Certificados    — emissão, carregamento, verificação X.509
  9. Serialização    — mkpair / unpair
"""

import os
import sys
import base64
import datetime
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
    load_der_public_key, load_pem_private_key, load_pem_public_key,
)
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID

# ─────────────── Constantes ──────────────────────────────────────────────────

PBKDF2_ITERATIONS  = 600_000   # NIST 2023
KEY_LENGTH         = 32         # 256 bits — AES-256, ChaCha20, HKDF output
SALT_SIZE          = 16         # 128 bits
NONCE_SIZE_AES     = 12         # AES-GCM recomenda 96 bits
NONCE_SIZE_CHACHA  = 12         # ChaCha20-Poly1305 usa 96 bits
RSA_KEY_SIZE       = 2048
RSA_BLOCK_SIZE     = 256        # bytes — output fixo de RSA-2048

# Parâmetros públicos DH — RFC 3526, grupo 2 (1024 bits)
DH_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
DH_G = 2


# ═══════════════════════════════════════════════════════════════════════════════
# 1. PBKDF2 — hash de passwords
#    Uso: server/managers/users.py (registar, autenticar)
#    Função irreversível. Apenas para passwords de baixa entropia.
# ═══════════════════════════════════════════════════════════════════════════════

def _derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Deriva 32 bytes a partir de password + salt via SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def hash_password(password: str) -> tuple[str, str]:
    """
    Gera salt aleatório e deriva hash da password.
    Devolve (salt_b64, hash_b64) prontos a guardar em JSON.
    """
    salt = os.urandom(SALT_SIZE)
    key  = _derive_key_from_password(password, salt)
    return base64.b64encode(salt).decode(), base64.b64encode(key).decode()


def verify_password(password: str, salt_b64: str, hash_b64: str) -> bool:
    """Verifica password contra hash guardado."""
    salt = base64.b64decode(salt_b64)
    key  = _derive_key_from_password(password, salt)
    return base64.b64encode(key).decode() == hash_b64


# ═══════════════════════════════════════════════════════════════════════════════
# 2. AES-GCM — cifra autenticada
#    Uso: canal cliente-servidor (network.py), E2EE (controllers/chat.py)
#    Garante: confidencialidade + integridade + autenticidade numa só operação.
#    A `key` deve ter 32 bytes e vir de fonte de alta entropia (DH+HKDF, urandom).
# ═══════════════════════════════════════════════════════════════════════════════

def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Cifra plaintext com AES-256-GCM.
    Devolve nonce(12) + ciphertext + tag(16).
    """
    nonce      = os.urandom(NONCE_SIZE_AES)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt(key: bytes, data: bytes) -> bytes:
    """
    Decifra dados produzidos por encrypt().
    Lança ValueError se a tag GCM for inválida.
    """
    nonce      = data[:NONCE_SIZE_AES]
    ciphertext = data[NONCE_SIZE_AES:]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise ValueError("Autenticação falhou — dados corrompidos ou alterados.")


# ═══════════════════════════════════════════════════════════════════════════════
# 3. RSA — geração, serialização, OAEP, PSS
#    Uso: registo (RSA-OAEP), STS (RSA-PSS), certificados
# ═══════════════════════════════════════════════════════════════════════════════

def rsa_generate_keypair():
    """Gera par de chaves RSA-2048."""
    return rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)


def rsa_serialize_private(private_key) -> bytes:
    """Chave privada RSA → bytes PEM (sem cifra; cifrar antes de gravar)."""
    return private_key.private_bytes(
        Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
    )


def rsa_serialize_public(private_key) -> bytes:
    """Chave pública RSA → bytes PEM."""
    return private_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )


def rsa_load_private(pem_bytes: bytes):
    """bytes PEM → objecto chave privada RSA."""
    return load_pem_private_key(pem_bytes, password=None)


def rsa_load_public(pem_bytes: bytes):
    """bytes PEM → objecto chave pública RSA."""
    return load_pem_public_key(pem_bytes)


def rsa_load_public_from_bytes(raw: bytes):
    """PEM bytes (pode ser str.encode) → objecto chave pública RSA."""
    if isinstance(raw, str):
        raw = raw.encode("ascii")
    return load_pem_public_key(raw)


def rsa_encrypt(public_key, data: bytes) -> bytes:
    """
    Cifra com RSA-OAEP-SHA256.
    Devolve 256 bytes para chaves RSA-2048.
    Limite de plaintext: ~190 bytes — para mais usar hybrid_encrypt.
    """
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    """Decifra RSA-OAEP-SHA256."""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_sign(private_key, data: bytes) -> bytes:
    """
    Assina data com RSA-PSS-SHA256.
    Devolve 256 bytes para chaves RSA-2048.
    Uso no STS: sig = rsa_sign(priv, mkpair(g_x, g_y))
    """
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def rsa_verify(public_key, signature: bytes, data: bytes) -> None:
    """
    Verifica assinatura RSA-PSS-SHA256.
    Lança InvalidSignature se inválida — nunca devolve False silenciosamente.
    """
    public_key.verify(
        signature,
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Cifra híbrida — RSA + AES-GCM
#    Uso: registo (cliente cifra para servidor; servidor cifra resposta).
#    Também útil para distribuir chave de grupo (cifrar group_key com RSA de cada membro).
# ═══════════════════════════════════════════════════════════════════════════════

def hybrid_encrypt(rsa_public_key, plaintext: bytes) -> bytes:
    """
    Cifra híbrida: gera chave AES one-time, cifra payload com AES-GCM,
    cifra a chave AES com RSA-OAEP.
    Devolve: encrypted_key(256 bytes) + nonce(12) + ciphertext + tag(16)
    """
    aes_key       = os.urandom(KEY_LENGTH)
    aes_blob      = encrypt(aes_key, plaintext)
    encrypted_key = rsa_encrypt(rsa_public_key, aes_key)
    return encrypted_key + aes_blob


def hybrid_decrypt(rsa_private_key, blob: bytes) -> bytes:
    """Inverso de hybrid_encrypt."""
    encrypted_key = blob[:RSA_BLOCK_SIZE]
    aes_blob      = blob[RSA_BLOCK_SIZE:]
    aes_key       = rsa_decrypt(rsa_private_key, encrypted_key)
    return decrypt(aes_key, aes_blob)


# ═══════════════════════════════════════════════════════════════════════════════
# 5. ChaCha20-Poly1305 — cifra autenticada de ficheiros locais
#    Uso: guardar chave privada RSA do cliente em disco cifrada com a password.
#    AEAD: garante integridade — qualquer alteração no ficheiro é detectada.
# ═══════════════════════════════════════════════════════════════════════════════

def encrypt_to_file(content: bytes, password: str, path: str) -> None:
    """
    Cifra content com ChaCha20-Poly1305 derivando chave da password (PBKDF2).
    Formato gravado: salt(16) + nonce(12) + ciphertext + tag(16)
    """
    salt  = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE_CHACHA)
    key   = _derive_key_from_password(password, salt)

    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, content, None)

    with open(path, "wb") as f:
        f.write(salt + nonce + ciphertext)


def decrypt_from_file(path: str, password: str) -> bytes:
    """
    Lê e decifra ficheiro produzido por encrypt_to_file().
    Lança ValueError se a password estiver errada ou se o ficheiro foi alterado.
    """
    with open(path, "rb") as f:
        data = f.read()

    salt       = data[:SALT_SIZE]
    nonce      = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE_CHACHA]
    ciphertext = data[SALT_SIZE + NONCE_SIZE_CHACHA:]
    key        = _derive_key_from_password(password, salt)

    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise ValueError("Password errada ou ficheiro corrompido.")


def local_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Cifra dados locais com ChaCha20-Poly1305.
    A chave deve ser de alta entropia (ex: derivada via HKDF).
    Formato: nonce(12) + ciphertext + tag(16)
    """
    nonce = os.urandom(NONCE_SIZE_CHACHA)
    ct    = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
    return nonce + ct


def local_decrypt(key: bytes, data: bytes) -> bytes:
    """
    Decifra dados produzidos por local_encrypt().
    Lança ValueError se a autenticação falhar (dados alterados ou chave errada).
    """
    nonce = data[:NONCE_SIZE_CHACHA]
    ct    = data[NONCE_SIZE_CHACHA:]
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ct, None)
    except InvalidTag:
        raise ValueError("Autenticação falhou — dados corrompidos ou chave errada.")


# ═══════════════════════════════════════════════════════════════════════════════
# 6. DH — Diffie-Hellman
#    Uso: STS handshake (network.py), handshake E2EE entre clientes (chat.py).
#    Pares sempre efémeros — descartados após derivar a chave de sessão.
# ═══════════════════════════════════════════════════════════════════════════════

def _dh_get_params():
    """Cria objecto DHParameters a partir dos parâmetros fixos p e g."""
    return dh.DHParameterNumbers(DH_P, DH_G).parameters()

def dh_generate_keypair() -> tuple:
    """
    Gera par DH efémero.
    Devolve (private_key, pub_bytes_DER).
    pub_bytes_DER é o que se envia pela rede.
    """
    params    = _dh_get_params()
    priv      = params.generate_private_key()
    pub_bytes = priv.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    return priv, pub_bytes

def dh_pub_bytes(private_key) -> bytes:
    """Extrai bytes DER da chave pública de um par DH (inverso de dh_generate_keypair[1])."""
    return private_key.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )

def dh_compute_shared(private_key, peer_pub_bytes: bytes) -> bytes:
    """
    Calcula o segredo partilhado bruto K = (g^peer)^private.
    Geralmente não é usado directamente — usar dh_derive_session_key.
    """
    peer_pub = load_der_public_key(peer_pub_bytes)
    return private_key.exchange(peer_pub)

# ═══════════════════════════════════════════════════════════════════════════════
# 7. HKDF — derivação de chaves
#    Uso: derivar session_key a partir do segredo DH; rotação (forward secrecy).
# ═══════════════════════════════════════════════════════════════════════════════

def hkdf_derive(input_key: bytes, info: bytes,
                length: int = KEY_LENGTH, salt: bytes | None = None) -> bytes:
    """
    Deriva chave criptográfica via HKDF-SHA256.
    O parâmetro info permite obter chaves distintas a partir do mesmo input.
    O parâmetro salt (opcional) muda o resultado — usado no E2E para vincular à sessão.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(input_key)

def dh_derive_session_key(private_key, peer_pub_bytes: bytes,
                          info: bytes = b"chat-session-key") -> bytes:
    """
    Conveniência: faz DH + HKDF numa só chamada.
    Devolve 32 bytes prontos para AES-GCM.
    """
    shared = dh_compute_shared(private_key, peer_pub_bytes)
    return hkdf_derive(shared, info)

def dh_derive_directional_keys(private_key, peer_pub_bytes: bytes,
                                gx_bytes: bytes, gy_bytes: bytes) -> tuple[bytes, bytes]:
    """
    Deriva duas chaves direccionais independentes a partir do segredo DH.
    salt = SHA256(g^x || g^y)
    chave_c2s = HKDF(g^(xy), salt, info="client-to-server")
    chave_s2c = HKDF(g^(xy), salt, info="server-to-client")
    Devolve (chave_c2s, chave_s2c).
    """
    shared = dh_compute_shared(private_key, peer_pub_bytes)
    salt = hashlib.sha256(gx_bytes + gy_bytes).digest()
    c2s = HKDF(
        algorithm=hashes.SHA256(), length=KEY_LENGTH,
        salt=salt, info=b"client-to-server",
    ).derive(shared)
    s2c = HKDF(
        algorithm=hashes.SHA256(), length=KEY_LENGTH,
        salt=salt, info=b"server-to-client",
    ).derive(shared)
    return c2s, s2c

def encrypt_counter(key: bytes, nonce: bytes, plaintext: bytes,
                    aad: bytes | None = None) -> bytes:
    """AES-256-GCM with a pre-built nonce. Returns nonce + ciphertext+tag."""
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt_counter(key: bytes, data: bytes,
                    aad: bytes | None = None) -> bytes:
    """Inverse of encrypt_counter. Expects nonce(12) + ciphertext+tag."""
    nonce = data[:NONCE_SIZE_AES]
    try:
        return AESGCM(key).decrypt(nonce, data[NONCE_SIZE_AES:], aad)
    except InvalidTag:
        raise ValueError("Autenticação AES-GCM falhou — dados corrompidos ou chave errada.")


def rotate_key(current_key: bytes) -> bytes:
    """
    Deriva próxima chave a partir da actual (forward secrecy leve).
    Após rotação, descartar a chave antiga da memória.

    Uso (a cada N mensagens):
        session_key = rotate_key(session_key)
    """
    return hkdf_derive(current_key, info=b"key-rotation")

def hmac_derive(key: bytes, info: str) -> bytes:
    """
    Deriva 32 bytes via HMAC-SHA256(key, info).
    Uso no ratchet simétrico E2E:
      msg_key       = hmac_derive(chain_key, "message")
      new_chain_key = hmac_derive(chain_key, "chain")
    """
    import hmac as _hmac
    return _hmac.new(key, info.encode("utf-8"), "sha256").digest()

# ═══════════════════════════════════════════════════════════════════════════════
# 8. Certificados X.509
#    Uso: servidor actua como CA — emite certs no registo dos clientes.
#    server.crt é distribuído com o cliente (fora de banda).
# ═══════════════════════════════════════════════════════════════════════════════

def cert_load(path: str):
    """Carrega certificado X.509 de ficheiro PEM."""
    with open(path, "rb") as f:
        return load_pem_x509_certificate(f.read())

def cert_load_bytes(pem_bytes: bytes):
    """Carrega certificado X.509 de bytes PEM (recebido pela rede ou da BD)."""
    return load_pem_x509_certificate(pem_bytes)

def cert_serialize(cert) -> bytes:
    """Certificado → bytes PEM."""
    return cert.public_bytes(Encoding.PEM)

def cert_get_public_key(cert):
    """Extrai chave pública RSA do certificado."""
    return cert.public_key()

def cert_verify(cert, ca_cert) -> None:
    """
    Valida que cert foi assinado pela CA.
    Lança excepção se inválido.
    """
    ca_cert.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )

def cert_issue(ca_private_key, subject_name: str,
               subject_public_key_pem: bytes, days: int = 365) -> bytes:
    """
    Servidor-CA emite certificado X.509 para um cliente.
    Devolve bytes PEM do certificado.
    """
    subject_public_key = load_pem_public_key(subject_public_key_pem)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)])
    issuer  = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "servidor")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days))
        .sign(ca_private_key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.PEM)

def cert_setup_server(output_dir: str = "server/ca") -> None:
    """
    Gera chave privada e certificado self-signed do servidor.
    Corre UMA VEZ antes de arrancar o servidor pela primeira vez.
    """
    os.makedirs(output_dir, exist_ok=True)
    private_key = rsa_generate_keypair()

    # Chave privada do servidor
    key_path = os.path.join(output_dir, "server.key")
    with open(key_path, "wb") as f:
        f.write(rsa_serialize_private(private_key))

    # Certificado self-signed
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "servidor")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )
    crt_path = os.path.join(output_dir, "server.crt")
    with open(crt_path, "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))

    print(f"[+] server.key e server.crt gerados em '{output_dir}'")
    print(f"[!] Copia '{crt_path}' para 'client/data/ca/server.crt'")

def cert_load_server(ca_dir: str = "server/ca") -> tuple:
    """
    Carrega chave privada e certificado do servidor.
    Devolve (private_key, cert).
    """
    with open(os.path.join(ca_dir, "server.key"), "rb") as f:
        private_key = rsa_load_private(f.read())
    cert = cert_load(os.path.join(ca_dir, "server.crt"))
    return private_key, cert

# ═══════════════════════════════════════════════════════════════════════════════
# 9. Serialização — mkpair / unpair
#    Uso: empacotar múltiplos campos numa só mensagem (handshakes, E2EE).
#    Para 3+ campos: aninhar — mkpair(a, mkpair(b, c))
# ═══════════════════════════════════════════════════════════════════════════════

def mkpair(x: bytes, y: bytes) -> bytes:
    """Serializa par (x, y). Prefixo de 2 bytes little-endian com tamanho de x."""
    return len(x).to_bytes(2, "little") + x + y


def unpair(xy: bytes) -> tuple[bytes, bytes]:
    """Separa bytes produzidos por mkpair. Devolve (x, y)."""
    len_x = int.from_bytes(xy[:2], "little")
    return xy[2:len_x + 2], xy[len_x + 2:]


# ═══════════════════════════════════════════════════════════════════════════════
# Setup do servidor
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "setup":
        cert_setup_server()
    else:
        print("Uso: python crypto.py setup")
        print("Gera server.key e server.crt em server/ca/")
