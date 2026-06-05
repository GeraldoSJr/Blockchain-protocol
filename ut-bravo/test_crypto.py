"""
Operação Cripto-Sentinela — UT-Bravo
Testes unitários de todas as operações criptográficas.

Execute com: python test_crypto.py
"""

import base64
import json
import sys
import traceback


def _ok(msg):
    print(f"  ✅ {msg}")


def _fail(msg, e=None):
    print(f"  ❌ {msg}")
    if e:
        print(f"     Erro: {e}")
    return False


def _secao(titulo):
    print(f"\n{'═' * 55}")
    print(f"  {titulo}")
    print(f"{'═' * 55}")


# ──────────────────────────────────────────────────────────
# 1. Geração de Chaves
# ──────────────────────────────────────────────────────────
def test_geracao_chaves():
    _secao("1. Geração de Chaves")
    from crypto import gerar_chaves_rsa, gerar_chaves_ecdsa, exportar_chaves_b64
    from cryptography.hazmat.primitives.asymmetric import rsa, ec

    # RSA
    priv_rsa, pub_rsa = gerar_chaves_rsa()
    assert isinstance(priv_rsa, rsa.RSAPrivateKey), "Privada RSA inválida"
    assert priv_rsa.key_size == 2048, "Tamanho da chave RSA != 2048"
    assert priv_rsa.public_key().public_numbers().e == 65537, "Expoente RSA != 65537"
    _ok("RSA-2048 gerado corretamente (expoente=65537)")

    # ECDSA
    priv_ec, pub_ec = gerar_chaves_ecdsa()
    assert isinstance(priv_ec, ec.EllipticCurvePrivateKey), "Privada ECDSA inválida"
    assert isinstance(priv_ec.curve, ec.SECP256R1), "Curva ECDSA deve ser secp256r1"
    _ok("ECDSA secp256r1 gerado corretamente")

    # Exportação Base64
    rsa_b64 = exportar_chaves_b64(priv_rsa, pub_rsa)
    ec_b64 = exportar_chaves_b64(priv_ec, pub_ec)
    assert rsa_b64["public_key"] and rsa_b64["private_key"]
    assert ec_b64["public_key"] and ec_b64["private_key"]
    _ok("Exportação Base64 DER/PKCS8 OK")

    return True


# ──────────────────────────────────────────────────────────
# 2. Serialização / Carregamento de Chaves
# ──────────────────────────────────────────────────────────
def test_serializacao_chaves():
    _secao("2. Serialização e Carregamento de Chaves")
    from crypto import (
        gerar_chaves_rsa, gerar_chaves_ecdsa,
        exportar_chaves_b64,
        carregar_chave_publica_rsa, carregar_chave_privada_rsa,
        carregar_chave_publica_ecdsa, carregar_chave_privada_ecdsa,
    )

    priv_rsa, pub_rsa = gerar_chaves_rsa()
    priv_ec, pub_ec = gerar_chaves_ecdsa()

    rsa_b64 = exportar_chaves_b64(priv_rsa, pub_rsa)
    ec_b64 = exportar_chaves_b64(priv_ec, pub_ec)

    # Carrega e re-exporta para verificar roundtrip
    pub_rsa2 = carregar_chave_publica_rsa(rsa_b64["public_key"])
    priv_rsa2 = carregar_chave_privada_rsa(rsa_b64["private_key"])
    assert pub_rsa2.public_numbers() == pub_rsa.public_numbers()
    _ok("RSA pública: roundtrip Base64 ↔ objeto OK")

    pub_ec2 = carregar_chave_publica_ecdsa(ec_b64["public_key"])
    priv_ec2 = carregar_chave_privada_ecdsa(ec_b64["private_key"])
    assert pub_ec2.public_numbers() == pub_ec.public_numbers()
    _ok("ECDSA pública: roundtrip Base64 ↔ objeto OK")

    return True


# ──────────────────────────────────────────────────────────
# 3. Hashing SHA-256
# ──────────────────────────────────────────────────────────
def test_hashing():
    _secao("3. Hashing SHA-256")
    from crypto import sha256, sha256_str

    # Vetor de teste padrão
    msg = b"abc"
    esperado = bytes.fromhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    resultado = sha256(msg)
    assert resultado == esperado, f"Hash incorreto: {resultado.hex()}"
    _ok("SHA-256 de 'abc' — vetor NIST correto")

    msg_str = "Atacar Sombra nas coordenadas: 22°54'S 43°10'W"
    h = sha256_str(msg_str)
    assert len(h) == 32
    _ok(f"SHA-256 de string UTF-8 — {len(h)*8} bits OK")

    return True


# ──────────────────────────────────────────────────────────
# 4. Assinatura e Verificação ECDSA
# ──────────────────────────────────────────────────────────
def test_ecdsa():
    _secao("4. Assinatura e Verificação ECDSA")
    from crypto import gerar_chaves_ecdsa, assinar_ecdsa, verificar_assinatura_ecdsa, sha256_str

    priv, pub = gerar_chaves_ecdsa()
    dados = sha256_str("Ordem de combate UT-Bravo")

    assinatura = assinar_ecdsa(priv, dados)
    assert isinstance(assinatura, bytes) and len(assinatura) > 0
    _ok(f"Assinatura gerada ({len(assinatura)} bytes DER)")

    # Verificação válida
    assert verificar_assinatura_ecdsa(pub, dados, assinatura)
    _ok("Verificação ECDSA: assinatura válida — OK")

    # Verificação inválida (dados adulterados)
    dados_adulterados = sha256_str("Ordem adulterada pela Sombra!")
    assert not verificar_assinatura_ecdsa(pub, dados_adulterados, assinatura)
    _ok("Verificação ECDSA: dados adulterados detectados — OK")

    # Verificação com chave errada
    _, pub2 = gerar_chaves_ecdsa()
    assert not verificar_assinatura_ecdsa(pub2, dados, assinatura)
    _ok("Verificação ECDSA: chave errada detectada — OK")

    return True


# ──────────────────────────────────────────────────────────
# 5. Criptografia RSA-OAEP (chave de sessão)
# ──────────────────────────────────────────────────────────
def test_rsa_oaep():
    _secao("5. RSA-OAEP — Cifração/Decifração de Chave de Sessão")
    import os
    from crypto import gerar_chaves_rsa, cifrar_chave_rsa, decifrar_chave_rsa

    priv, pub = gerar_chaves_rsa()
    chave_sessao = os.urandom(32)  # 256 bits

    cifrado = cifrar_chave_rsa(pub, chave_sessao)
    assert isinstance(cifrado, bytes) and len(cifrado) == 256  # RSA-2048 → 256 bytes
    _ok(f"Chave de sessão cifrada ({len(cifrado)} bytes)")

    recuperado = decifrar_chave_rsa(priv, cifrado)
    assert recuperado == chave_sessao
    _ok("Chave de sessão recuperada corretamente")

    # Chave privada errada
    priv2, _ = gerar_chaves_rsa()
    try:
        decifrar_chave_rsa(priv2, cifrado)
        return _fail("Deveria ter falhado com chave errada")
    except Exception:
        _ok("Chave privada errada → decifração falha (esperado)")

    return True


# ──────────────────────────────────────────────────────────
# 6. Criptografia Simétrica AES-256-GCM
# ──────────────────────────────────────────────────────────
def test_aes_gcm():
    _secao("6. AES-256-GCM — Cifração/Decifração")
    import os
    from crypto import cifrar_aes_gcm, decifrar_aes_gcm

    chave = os.urandom(32)
    plaintext = "Mover para coordenada 22°54'S 43°10'W — URGENTE".encode()

    ciphertext, tag, nonce = cifrar_aes_gcm(chave, plaintext)
    assert ciphertext != plaintext
    assert len(tag) == 16  # GCM tag = 128 bits
    assert len(nonce) == 12  # Nonce GCM = 96 bits
    _ok(f"Cifrado: {len(ciphertext)}B | Tag: {len(tag)}B | Nonce: {len(nonce)}B")

    recuperado = decifrar_aes_gcm(chave, ciphertext, tag, nonce)
    assert recuperado == plaintext
    _ok("Decifrado corretamente")

    # Tag adulterada deve ser detectada
    tag_adulterada = bytes([b ^ 0xFF for b in tag])
    try:
        decifrar_aes_gcm(chave, ciphertext, tag_adulterada, nonce)
        return _fail("AES-GCM deveria detectar adulteração na tag")
    except Exception:
        _ok("Tag adulterada detectada pelo AES-GCM — integridade garantida")

    # Ciphertext adulterado
    ct_adulterado = bytes([ciphertext[0] ^ 0x01]) + ciphertext[1:]
    try:
        decifrar_aes_gcm(chave, ct_adulterado, tag, nonce)
        return _fail("AES-GCM deveria detectar adulteração no ciphertext")
    except Exception:
        _ok("Ciphertext adulterado detectado pelo AES-GCM — integridade garantida")

    return True


# ──────────────────────────────────────────────────────────
# 7. Empacotamento / Desempacotamento de Mensagem Completa
# ──────────────────────────────────────────────────────────
def test_mensagem_completa():
    _secao("7. Protocolo Completo — Empacotamento e Desempacotamento")
    from crypto import (
        gerar_chaves_rsa, gerar_chaves_ecdsa,
        empacotar_mensagem, desempacotar_mensagem,
    )

    # Simula dois participantes: UT-Alfa (remetente) e UT-Bravo (receptor)
    priv_rsa_alfa, pub_rsa_alfa = gerar_chaves_rsa()
    priv_ec_alfa, pub_ec_alfa = gerar_chaves_ecdsa()

    priv_rsa_bravo, pub_rsa_bravo = gerar_chaves_rsa()
    priv_ec_bravo, pub_ec_bravo = gerar_chaves_ecdsa()

    mensagem_original = "Atacar Sombra nas coordenadas: 22°54'S 43°10'W — CLASSIFICADO"

    # Alfa empacota mensagem para Bravo
    payload = empacotar_mensagem(
        plaintext=mensagem_original,
        chave_publica_rsa_destinatario=pub_rsa_bravo,
        chave_privada_ecdsa_remetente=priv_ec_alfa,
        id_remetente="ut-alfa",
    )
    payload_dict = json.loads(payload)
    campos_obrigatorios = [
        "id_unidade", "ciphertext_b64", "tag_autenticacao_b64",
        "nonce_b64", "chave_sessao_cifrada_b64", "assinatura_b64"
    ]
    for campo in campos_obrigatorios:
        assert campo in payload_dict, f"Campo ausente: {campo}"
    _ok(f"Pacote gerado com todos os {len(campos_obrigatorios)} campos obrigatórios")

    # Bravo desempacota
    def obter_ecdsa(id_unidade):
        return pub_ec_alfa if id_unidade == "ut-alfa" else None

    resultado = desempacotar_mensagem(
        payload_json=payload,
        chave_privada_rsa_receptor=priv_rsa_bravo,
        obter_chave_publica_ecdsa=obter_ecdsa,
    )
    assert resultado["sucesso"], f"Falha inesperada: {resultado.get('erro')}"
    assert resultado["mensagem"] == mensagem_original
    assert resultado["id_remetente"] == "ut-alfa"
    _ok("Desempacotamento e validação completa — OK")
    _ok(f"Mensagem recuperada: '{resultado['mensagem'][:50]}...'")

    # Chave RSA errada (mensagem destinada a outro)
    resultado2 = desempacotar_mensagem(
        payload_json=payload,
        chave_privada_rsa_receptor=priv_rsa_alfa,  # Chave errada!
        obter_chave_publica_ecdsa=obter_ecdsa,
    )
    assert not resultado2["sucesso"]
    _ok("Chave RSA errada detectada (mensagem não era para nós)")

    # Remetente desconhecido
    resultado3 = desempacotar_mensagem(
        payload_json=payload,
        chave_privada_rsa_receptor=priv_rsa_bravo,
        obter_chave_publica_ecdsa=lambda _: None,  # Sem chaves
    )
    assert not resultado3["sucesso"]
    _ok("Remetente sem chave registrada detectado (unidade desconhecida)")

    # Payload adulterado
    payload_adulterado = json.dumps({
        **payload_dict,
        "ciphertext_b64": base64.b64encode(b"dados adulterados pela Sombra!").decode(),
    })
    resultado4 = desempacotar_mensagem(
        payload_json=payload_adulterado,
        chave_privada_rsa_receptor=priv_rsa_bravo,
        obter_chave_publica_ecdsa=obter_ecdsa,
    )
    assert not resultado4["sucesso"]
    _ok("Adulteração do ciphertext detectada (ataque da Sombra bloqueado)")

    return True


# ──────────────────────────────────────────────────────────
# 8. Revogação
# ──────────────────────────────────────────────────────────
def test_revogacao():
    _secao("8. Revogação de Unidades")
    from crypto import (
        gerar_chaves_ecdsa, exportar_chaves_b64,
        criar_pacote_revogacao, validar_pacote_revogacao,
    )

    priv_alfa, pub_alfa = gerar_chaves_ecdsa()
    alfa_b64 = exportar_chaves_b64(priv_alfa, pub_alfa)

    def obter_ecdsa(id_unidade):
        if id_unidade == "ut-alfa":
            from crypto import carregar_chave_publica_ecdsa
            return carregar_chave_publica_ecdsa(alfa_b64["public_key"])
        return None

    # Cria pacote de revogação válido
    pacote = criar_pacote_revogacao("ut-alfa", "ut-charlie", priv_alfa)
    pacote_dict = json.loads(pacote)
    assert "remetente" in pacote_dict
    assert "revogacao" in pacote_dict
    assert "assinatura_b64" in pacote_dict
    _ok("Pacote de revogação criado com campos corretos")

    # Valida pacote legítimo
    resultado = validar_pacote_revogacao(pacote, obter_ecdsa)
    assert resultado["sucesso"], f"Falha: {resultado.get('erro')}"
    assert resultado["unidade_revogada"] == "ut-charlie"
    assert resultado["remetente"] == "ut-alfa"
    _ok(f"Revogação válida: {resultado['remetente']} revogou {resultado['unidade_revogada']}")

    # Assinatura forjada (Sombra tentando forjar revogação)
    pacote_forjado = json.dumps({
        **pacote_dict,
        "assinatura_b64": base64.b64encode(b"assinatura forjada pela sombra").decode(),
    })
    resultado2 = validar_pacote_revogacao(pacote_forjado, obter_ecdsa)
    assert not resultado2["sucesso"]
    _ok("Revogação forjada pela Sombra detectada e rejeitada")

    # Remetente desconhecido
    resultado3 = validar_pacote_revogacao(pacote, lambda _: None)
    assert not resultado3["sucesso"]
    _ok("Revogação de unidade desconhecida rejeitada")

    return True


# ──────────────────────────────────────────────────────────
# 9. Chaves do Oráculo
# ──────────────────────────────────────────────────────────
def test_chaves_oraculo():
    _secao("9. Carregamento das Chaves Públicas do Oráculo")
    from crypto import carregar_chave_publica_rsa, carregar_chave_publica_ecdsa
    from unidade_tatica import ORACULO_RSA_PUB_B64, ORACULO_ECDSA_PUB_B64

    try:
        rsa_key = carregar_chave_publica_rsa(ORACULO_RSA_PUB_B64.replace("\n", ""))
        assert rsa_key.key_size == 2048
        _ok(f"Chave RSA do Oráculo carregada ({rsa_key.key_size} bits)")
    except Exception as e:
        return _fail("Falha ao carregar RSA do Oráculo", e)

    try:
        ecdsa_key = carregar_chave_publica_ecdsa(ORACULO_ECDSA_PUB_B64.replace("\n", ""))
        _ok(f"Chave ECDSA do Oráculo carregada (curva: {ecdsa_key.curve.name})")
    except Exception as e:
        return _fail("Falha ao carregar ECDSA do Oráculo", e)

    return True


# ──────────────────────────────────────────────────────────
# Runner
# ──────────────────────────────────────────────────────────

TESTES = [
    test_geracao_chaves,
    test_serializacao_chaves,
    test_hashing,
    test_ecdsa,
    test_rsa_oaep,
    test_aes_gcm,
    test_mensagem_completa,
    test_revogacao,
    test_chaves_oraculo,
]


def main():
    print("\n" + "╔" + "═" * 55 + "╗")
    print("║      🧪  TESTES — OPERAÇÃO CRIPTO-SENTINELA UT-BRAVO     ║")
    print("╚" + "═" * 55 + "╝")

    passou = 0
    falhou = 0
    erros = []

    for teste in TESTES:
        try:
            ok = teste()
            if ok is not False:
                passou += 1
            else:
                falhou += 1
                erros.append(teste.__name__)
        except Exception as e:
            falhou += 1
            erros.append(teste.__name__)
            print(f"\n  💥 EXCEÇÃO em {teste.__name__}:")
            traceback.print_exc()

    print(f"\n{'═' * 57}")
    print(f"  📊 Resultado: {passou}/{passou + falhou} testes passaram")
    if erros:
        print(f"  ❌ Falhas: {', '.join(erros)}")
    else:
        print("  🏆 Todos os testes passaram! UT-Bravo pronta para operação.")
    print(f"{'═' * 57}\n")

    sys.exit(0 if falhou == 0 else 1)


if __name__ == "__main__":
    main()
