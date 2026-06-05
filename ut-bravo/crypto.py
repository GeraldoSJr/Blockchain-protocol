"""
Operação Cripto-Sentinela — UT-Bravo
Módulo de Criptografia: RSA, ECDSA (secp256r1), AES-GCM, SHA-256
"""

import base64
import hashlib
import json
import os
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ─────────────────────────────────────────────
#  Geração de Chaves
# ─────────────────────────────────────────────

def gerar_chaves_rsa():
    """Gera par de chaves RSA-2048 com expoente público 65537."""
    privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return privada, privada.public_key()


def gerar_chaves_ecdsa():
    """Gera par de chaves ECDSA na curva secp256r1."""
    privada = ec.generate_private_key(ec.SECP256R1())
    return privada, privada.public_key()


# ─────────────────────────────────────────────
#  Serialização / Exportação
# ─────────────────────────────────────────────

def exportar_chaves_b64(chave_privada, chave_publica):
    """Serializa par de chaves em Base64 (DER/PKCS8)."""
    priv_bytes = chave_privada.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = chave_publica.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "private_key": base64.b64encode(priv_bytes).decode(),
        "public_key": base64.b64encode(pub_bytes).decode(),
    }


def carregar_chave_publica_rsa(b64_str: str):
    """Carrega chave pública RSA a partir de string Base64 DER."""
    key_bytes = base64.b64decode(b64_str)
    return serialization.load_der_public_key(key_bytes)


def carregar_chave_publica_ecdsa(b64_str: str):
    """Carrega chave pública ECDSA a partir de string Base64 DER."""
    key_bytes = base64.b64decode(b64_str)
    return serialization.load_der_public_key(key_bytes)


def carregar_chave_privada_rsa(b64_str: str):
    """Carrega chave privada RSA a partir de string Base64 DER/PKCS8."""
    key_bytes = base64.b64decode(b64_str)
    return serialization.load_der_private_key(key_bytes, password=None)


def carregar_chave_privada_ecdsa(b64_str: str):
    """Carrega chave privada ECDSA a partir de string Base64 DER/PKCS8."""
    key_bytes = base64.b64decode(b64_str)
    return serialization.load_der_private_key(key_bytes, password=None)


# ─────────────────────────────────────────────
#  Hashing
# ─────────────────────────────────────────────

def sha256(data: bytes) -> bytes:
    """Calcula SHA-256 de dados binários."""
    return hashlib.sha256(data).digest()


def sha256_str(texto: str) -> bytes:
    """Calcula SHA-256 de uma string UTF-8."""
    return sha256(texto.encode("utf-8"))


# ─────────────────────────────────────────────
#  Assinatura ECDSA
# ─────────────────────────────────────────────

def assinar_ecdsa(chave_privada_ecdsa, dados: bytes) -> bytes:
    """
    Assina os dados com ECDSA (secp256r1) usando SHA-256.
    Retorna a assinatura DER em bytes.
    """
    assinatura = chave_privada_ecdsa.sign(dados, ec.ECDSA(hashes.SHA256()))
    return assinatura


def verificar_assinatura_ecdsa(chave_publica_ecdsa, dados: bytes, assinatura: bytes) -> bool:
    """
    Verifica assinatura ECDSA.
    Retorna True se válida, False caso contrário.
    """
    try:
        chave_publica_ecdsa.verify(assinatura, dados, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────
#  Criptografia RSA (chave de sessão)
# ─────────────────────────────────────────────

def cifrar_chave_rsa(chave_publica_rsa, chave_sessao: bytes) -> bytes:
    """Cifra chave de sessão AES com RSA-OAEP."""
    return chave_publica_rsa.encrypt(
        chave_sessao,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decifrar_chave_rsa(chave_privada_rsa, chave_cifrada: bytes) -> bytes:
    """Decifra chave de sessão AES com RSA-OAEP."""
    return chave_privada_rsa.decrypt(
        chave_cifrada,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ─────────────────────────────────────────────
#  Criptografia Simétrica AES-256-GCM
# ─────────────────────────────────────────────

def cifrar_aes_gcm(chave_sessao: bytes, plaintext: bytes):
    """
    Cifra plaintext com AES-256-GCM.
    Retorna (ciphertext, tag, nonce) — cada um em bytes.
    Nota: AESGCM retorna ciphertext||tag concatenados;
    separamos os últimos 16 bytes como tag.
    """
    nonce = os.urandom(12)  # 96 bits recomendado para GCM
    aesgcm = AESGCM(chave_sessao)
    ct_com_tag = aesgcm.encrypt(nonce, plaintext, None)
    ciphertext = ct_com_tag[:-16]
    tag = ct_com_tag[-16:]
    return ciphertext, tag, nonce


def decifrar_aes_gcm(chave_sessao: bytes, ciphertext: bytes, tag: bytes, nonce: bytes) -> bytes:
    """
    Decifra e autentica com AES-256-GCM.
    Lança exceção se a tag de autenticação falhar.
    """
    aesgcm = AESGCM(chave_sessao)
    ct_com_tag = ciphertext + tag
    return aesgcm.decrypt(nonce, ct_com_tag, None)


# ─────────────────────────────────────────────
#  Empacotamento / Desempacotamento de Mensagens
# ─────────────────────────────────────────────

def empacotar_mensagem(
    plaintext: str,
    chave_publica_rsa_destinatario,
    chave_privada_ecdsa_remetente,
    id_remetente: str,
) -> str:
    """
    Cria o pacote de mensagem segura conforme o protocolo Cripto-Sentinela.

    Passos:
      1. Hash SHA-256 da mensagem original
      2. AES-256-GCM da mensagem
      3. RSA-OAEP da chave de sessão
      4. ECDSA sobre o hash SHA-256 da mensagem
    
    Retorna JSON string pronto para publicar no MQTT.
    """
    msg_bytes = plaintext.encode("utf-8")

    # 1. Hash da mensagem original
    hash_msg = sha256(msg_bytes)

    # 2. Gera chave de sessão e cifra a mensagem
    chave_sessao = os.urandom(32)  # AES-256
    ciphertext, tag, nonce = cifrar_aes_gcm(chave_sessao, msg_bytes)

    # 3. Cifra a chave de sessão com RSA do destinatário
    chave_sessao_cifrada = cifrar_chave_rsa(chave_publica_rsa_destinatario, chave_sessao)

    # 4. Assina o hash SHA-256 da mensagem com ECDSA
    assinatura = assinar_ecdsa(chave_privada_ecdsa_remetente, hash_msg)

    pacote = {
        "id_unidade": id_remetente,
        "ciphertext_b64": base64.b64encode(ciphertext).decode(),
        "tag_autenticacao_b64": base64.b64encode(tag).decode(),
        "nonce_b64": base64.b64encode(nonce).decode(),
        "chave_sessao_cifrada_b64": base64.b64encode(chave_sessao_cifrada).decode(),
        "assinatura_b64": base64.b64encode(assinatura).decode(),
    }
    return json.dumps(pacote)


def desempacotar_mensagem(
    payload_json: str,
    chave_privada_rsa_receptor,
    obter_chave_publica_ecdsa,  # callable(id_unidade) -> chave_publica_ecdsa | None
) -> dict:
    """
    Valida e decifra uma mensagem segura.

    Retorna dict com:
      - sucesso: bool
      - mensagem: str (se sucesso)
      - id_remetente: str
      - erro: str (se falhou)

    Passos (ordem CRÍTICA):
      1. Decodifica Base64 de todos os campos
      2. Decifra chave de sessão com RSA privado
      3. Decifra mensagem com AES-GCM (verifica tag automaticamente)
      4. Obtém chave pública ECDSA do remetente
      5. Verifica assinatura ECDSA sobre SHA-256 da mensagem
    """
    try:
        pacote = json.loads(payload_json)
    except json.JSONDecodeError as e:
        return {"sucesso": False, "erro": f"JSON inválido: {e}"}

    id_remetente = pacote.get("id_unidade", "desconhecido")

    try:
        ciphertext = base64.b64decode(pacote["ciphertext_b64"])
        tag = base64.b64decode(pacote["tag_autenticacao_b64"])
        nonce = base64.b64decode(pacote["nonce_b64"])
        chave_sessao_cifrada = base64.b64decode(pacote["chave_sessao_cifrada_b64"])
        assinatura = base64.b64decode(pacote["assinatura_b64"])
    except Exception as e:
        return {"sucesso": False, "erro": f"Erro ao decodificar Base64: {e}", "id_remetente": id_remetente}

    # Passo 2: Decifra chave de sessão
    try:
        chave_sessao = decifrar_chave_rsa(chave_privada_rsa_receptor, chave_sessao_cifrada)
    except Exception as e:
        return {
            "sucesso": False,
            "erro": f"Falha ao decifrar chave de sessão (mensagem não era para nós?): {e}",
            "id_remetente": id_remetente,
        }

    # Passo 3: Decifra mensagem (AES-GCM verifica tag automaticamente)
    try:
        plaintext_bytes = decifrar_aes_gcm(chave_sessao, ciphertext, tag, nonce)
        plaintext = plaintext_bytes.decode("utf-8")
    except Exception as e:
        return {
            "sucesso": False,
            "erro": f"Falha na decifração AES-GCM (possível adulteração pela Sombra!): {e}",
            "id_remetente": id_remetente,
        }

    # Passo 4: Obtém chave pública ECDSA do remetente
    chave_publica_ecdsa = obter_chave_publica_ecdsa(id_remetente)
    if chave_publica_ecdsa is None:
        return {
            "sucesso": False,
            "erro": f"Chave pública ECDSA de '{id_remetente}' não encontrada. Unidade desconhecida ou revogada.",
            "id_remetente": id_remetente,
        }

    # Passo 5: Verifica assinatura ECDSA
    hash_msg = sha256(plaintext_bytes)
    if not verificar_assinatura_ecdsa(chave_publica_ecdsa, hash_msg, assinatura):
        return {
            "sucesso": False,
            "erro": f"Assinatura ECDSA inválida! Mensagem de '{id_remetente}' pode ser forjada pela Sombra!",
            "id_remetente": id_remetente,
        }

    return {
        "sucesso": True,
        "mensagem": plaintext,
        "id_remetente": id_remetente,
    }


# ─────────────────────────────────────────────
#  Revogação
# ─────────────────────────────────────────────

def criar_pacote_revogacao(
    id_remetente: str,
    unidade_revogada: str,
    chave_privada_ecdsa_remetente,
) -> str:
    """
    Cria e assina um pacote de revogação.
    Retorna JSON string pronto para publicar no MQTT.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    mensagem_revogacao = {
        "unidade_revogada": unidade_revogada,
        "timestamp": timestamp,
    }
    msg_json = json.dumps(mensagem_revogacao, separators=(",", ":"))
    hash_msg = sha256(msg_json.encode("utf-8"))
    assinatura = assinar_ecdsa(chave_privada_ecdsa_remetente, hash_msg)

    pacote = {
        "remetente": id_remetente,
        "revogacao": mensagem_revogacao,
        "assinatura_b64": base64.b64encode(assinatura).decode(),
    }
    return json.dumps(pacote)


def validar_pacote_revogacao(
    payload_json: str,
    obter_chave_publica_ecdsa,  # callable(id_unidade) -> chave_publica_ecdsa | None
) -> dict:
    """
    Valida um pacote de revogação recebido.
    Retorna dict com sucesso, remetente, unidade_revogada, erro.
    """
    try:
        pacote = json.loads(payload_json)
    except json.JSONDecodeError as e:
        return {"sucesso": False, "erro": f"JSON inválido: {e}"}

    remetente = pacote.get("remetente", "desconhecido")
    revogacao = pacote.get("revogacao")
    assinatura_b64 = pacote.get("assinatura_b64")

    if not revogacao or not assinatura_b64:
        return {"sucesso": False, "erro": "Pacote de revogação malformado.", "remetente": remetente}

    chave_publica_ecdsa = obter_chave_publica_ecdsa(remetente)
    if chave_publica_ecdsa is None:
        return {
            "sucesso": False,
            "erro": f"Chave pública ECDSA de '{remetente}' não encontrada.",
            "remetente": remetente,
        }

    try:
        assinatura = base64.b64decode(assinatura_b64)
    except Exception as e:
        return {"sucesso": False, "erro": f"Base64 inválido na assinatura: {e}", "remetente": remetente}

    msg_json = json.dumps(revogacao, separators=(",", ":"))
    hash_msg = sha256(msg_json.encode("utf-8"))

    if not verificar_assinatura_ecdsa(chave_publica_ecdsa, hash_msg, assinatura):
        return {
            "sucesso": False,
            "erro": f"Assinatura de revogação inválida de '{remetente}'! Possível ataque da Sombra.",
            "remetente": remetente,
        }

    return {
        "sucesso": True,
        "remetente": remetente,
        "unidade_revogada": revogacao.get("unidade_revogada"),
        "timestamp": revogacao.get("timestamp"),
    }
