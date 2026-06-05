# 🛡️ Operação Cripto-Sentinela — UT-Bravo

**Comando de Defesa Cibernética (CDCiber)**  
Disciplina: DLT (Blockchain) 2026.1 — Laboratório 02

---

## Visão Geral

Implementação completa do protocolo de comunicação segura para a **UT-Bravo**, garantindo:

| Propriedade | Mecanismo |
|---|---|
| **Confidencialidade** | AES-256-GCM (chave de sessão efêmera) |
| **Integridade** | AES-GCM tag + SHA-256 |
| **Autenticidade** | ECDSA (secp256r1) |
| **Não-repúdio** | Assinatura ECDSA sobre hash da mensagem |
| **Controle de Acesso** | Lista de revogação persistente + validação de assinatura |

---

## Estrutura do Projeto

```
ut-bravo/
├── main.py               # Interface de linha de comando interativa
├── unidade_tatica.py     # Orquestrador principal (lógica de negócio)
├── crypto.py             # Módulo criptográfico (RSA, ECDSA, AES-GCM, SHA-256)
├── gerenciador_chaves.py # Gestão de chaves (persistência, revogação)
├── mqtt_client.py        # Comunicação MQTT com o CCU
├── test_crypto.py        # Testes unitários completos
├── requirements.txt      # Dependências Python
│
# Gerados em runtime:
├── minhas_chaves.json          # Par de chaves próprias (RSA + ECDSA)
├── chaves_confiaveis.json      # Chaves públicas de outras UTs
└── unidades_revogadas.json     # Lista de revogação local
```

---

## Instalação

```bash
pip install -r requirements.txt
```

**Dependências:**
- `cryptography >= 41.0.0` — operações criptográficas
- `paho-mqtt >= 1.6.1` — comunicação com o CCU (HiveMQ)

---

## Execução

### Modo interativo (CLI)

```bash
python main.py
```

### Comandos disponíveis

| Comando | Descrição |
|---|---|
| `id` / `identidade` | Publica chaves públicas no CCU (IFF) |
| `enviar <UT> <msg>` | Envia mensagem segura para outra UT |
| `eco` | Envia comando echo ao Oráculo |
| `revogar <UT>` | Revoga unidade comprometida |
| `chaves` | Lista UTs com chaves registradas |
| `revogadas` | Lista unidades revogadas |
| `status` | Status da conexão MQTT |
| `log` | Log de eventos de segurança |
| `sair` | Encerra a unidade tática |

**Exemplo de sessão:**
```
UT-Bravo> id
✅ Identidade publicada!

UT-Bravo> enviar ut-alfa Mover para coordenada 22°54'S 43°10'W
✅ Mensagem enviada para ut-alfa!

UT-Bravo> eco
✅ Eco enviado! Aguarde resposta no canal direto...

UT-Bravo> revogar ut-charlie
⚠️  Confirmar revogação de 'ut-charlie'? (s/N): s
🚫 Ordem de revogação emitida para ut-charlie!
```

### Testes unitários

```bash
python test_crypto.py
```

---

## Protocolo de Comunicação

### Tópicos MQTT

| Tópico | Finalidade |
|---|---|
| `sisdef/broadcast/chaves/ut-bravo` | Publicação de identidade (IFF) |
| `sisdef/direto/ut-bravo` | Recepção de mensagens diretas |
| `sisdef/broadcast/revogacao` | Revogações (broadcast) |
| `sisdef/direto/oraculo` | Envio ao Oráculo |

### Formato da Mensagem Segura

```json
{
  "id_unidade": "ut-bravo",
  "ciphertext_b64": "Base64(AES-GCM(mensagem))",
  "tag_autenticacao_b64": "Base64(GCM-tag)",
  "nonce_b64": "Base64(nonce-96bits)",
  "chave_sessao_cifrada_b64": "Base64(RSA-OAEP(chave-sessao))",
  "assinatura_b64": "Base64(ECDSA(SHA256(mensagem)))"
}
```

### Processo de Envio

1. Calcula SHA-256 da mensagem original
2. Gera chave de sessão AES-256 efêmera (32 bytes aleatórios)
3. Cifra mensagem com AES-256-GCM → `ciphertext`, `tag`, `nonce`
4. Cifra chave de sessão com RSA-OAEP (chave pública do destinatário)
5. Assina SHA-256 da mensagem com ECDSA (chave privada do remetente)

### Processo de Recepção (ordem crítica)

1. Parse JSON e decodifica todos os campos Base64
2. Decifra chave de sessão com RSA-OAEP (chave privada própria)
3. Decifra mensagem com AES-256-GCM (verifica tag automaticamente)
4. Obtém chave pública ECDSA do remetente via CCU
5. Verifica assinatura ECDSA sobre SHA-256 da mensagem decifrada

---

## Decisões de Implementação

### Por que AES-GCM e não CBC ou CTR?

AES-GCM é um modo **AEAD (Authenticated Encryption with Associated Data)**: cifra e autentica em uma única operação. O CBC requer um MAC separado (e pode ser vulnerável a ataques de padding oracle). O CTR oferece confidencialidade mas não integridade nativa. O GCM fornece ambos com desempenho excelente, sendo o padrão para TLS 1.3.

### Por que ECDSA e não HMAC?

HMAC é um código de autenticação de mensagem com **chave simétrica compartilhada** — requer que ambas as partes conheçam o segredo, o que implica um canal seguro prévio para troca da chave. ECDSA usa **chave assimétrica**: a chave privada nunca sai do remetente, e qualquer um com a chave pública pode verificar. Isso garante **não-repúdio** (o remetente não pode negar a autoria), propriedade ausente no HMAC.

### Por que RSA-OAEP para a chave de sessão?

RSA-OAEP é o esquema de padding seguro para RSA (PKCS#1 v2.1). O padding antigo PKCS#1 v1.5 é vulnerável a ataques como Bleichenbacher. OAEP com SHA-256 é resistente a ataques de texto cifrado escolhido (CCA2).

### Por que chave de sessão efêmera (hybrid encryption)?

RSA-2048 só consegue cifrar até ~190 bytes diretamente. Além disso, a criptografia assimétrica é computacionalmente cara. O padrão da indústria (TLS, PGP, Signal) é usar **criptografia híbrida**: cifra os dados com AES (rápido, sem limite de tamanho), e cifra apenas a chave AES com RSA.

---

## Identidade Criptográfica (IFF)

```json
{
  "id_unidade": "ut-bravo",
  "chave_publica_rsa": "MIIBIjAN...",
  "chave_publica_eddsa": "MFkwEwYH..."
}
```

Publicado com `retain=True` no broker HiveMQ para garantir que novas UTs recebam a identidade imediatamente ao se inscreverem.

---

## Broker MQTT

- **Endereço:** `broker.hivemq.com:1883`
- **Protocolo:** MQTT 3.1.1
- **Canal:** público (todo tráfego visível à Sombra — daí a necessidade de criptografia end-to-end)
