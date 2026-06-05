"""
Operação Cripto-Sentinela — UT-Bravo
Unidade Tática: orquestrador principal do protocolo de comunicação segura.
"""

import json
import logging
import threading
import time
from datetime import datetime, timezone

from crypto import (
    criar_pacote_revogacao,
    desempacotar_mensagem,
    empacotar_mensagem,
    validar_pacote_revogacao,
)
from gerenciador_chaves import GerenciadorChaves
from mqtt_client import ClienteMQTT

logger = logging.getLogger("UT-Bravo")

ID_UNIDADE = "ut-bravo"

# Chaves públicas do Oráculo (fornecidas no README)
ORACULO_RSA_PUB_B64 = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0JYEsxupPYOio+u8xHdzSNLQgQoPwFx/qceH"
    "QJPy2KzNSCXz3FFyKkXaso4UTorzy8XXDv5WkRC1AlDDVu28ANXlrZqLyjLZ8DdplHig2KSxYV5MXA5T"
    "yqMDeCAW5CWi+na5Xwr9IbtuTfCv65YeB3QRgZWjZ4oVxpGVek+4dec0qChNl6pL9KmgI4u5CHHC8d7"
    "z6MovK0+eN0aMIT2bWgri29tT9sDCoHEGaab1576+SXK3iDXlLkeehJ/h72lqu3HmSL/B5ZE+pKLVLJo"
    "gSwwMCTejrfTXf5acj9EOq83wGNLTjHIKr2iMz+SZzFS4vxk6qMgltCXjBZfXalzLnwIDAQAB"
)
ORACULO_ECDSA_PUB_B64 = (
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfmgdDET1IKOR2OxLI9KBBzFB97GyrJKipAuwSrMhDn1w"
    "93ieoCb7etbYX5/wrUic9xX5LQbUdgyKSRuCnTPAeQ=="
)


class UnidadeTatica:
    """
    Implementação completa da Unidade Tática UT-Bravo.

    Responsabilidades:
      - Identidade criptográfica (IFF)
      - Envio e recepção de mensagens seguras
      - Revogação de unidades comprometidas
      - Gerenciamento de chaves confiáveis
    """

    def __init__(self):
        logger.info("=" * 60)
        logger.info(f"  🪖  INICIANDO UT-BRAVO — Operação Cripto-Sentinela")
        logger.info("=" * 60)

        self.id_unidade = ID_UNIDADE
        self.gerenciador = GerenciadorChaves()
        self.mqtt = ClienteMQTT(ID_UNIDADE)
        self._log_seguranca: list = []

        # Injeta callbacks MQTT
        self.mqtt.on_chaves_recebidas = self._processar_chaves_recebidas
        self.mqtt.on_mensagem_recebida = self._processar_mensagem_recebida
        self.mqtt.on_revogacao_recebida = self._processar_revogacao_recebida

        # Pré-carrega chaves do Oráculo
        self._registrar_oraculo()

    # ─────────────────────────────────────────────
    #  Inicialização
    # ─────────────────────────────────────────────

    def _registrar_oraculo(self):
        """Registra as chaves públicas do Oráculo na lista confiável."""
        try:
            self.gerenciador.adicionar_chave_confiavel(
                "oraculo",
                ORACULO_RSA_PUB_B64.replace("\n", ""),
                ORACULO_ECDSA_PUB_B64.replace("\n", ""),
            )
            logger.info("🔑 Chaves do Oráculo registradas.")
        except Exception as e:
            logger.error(f"❌ Falha ao registrar chaves do Oráculo: {e}")

    def iniciar(self) -> bool:
        """Conecta ao CCU e publica identidade."""
        if not self.mqtt.conectar():
            return False

        # Aguarda um momento para garantir inscrições ativas
        time.sleep(1)

        # Publica identidade no CCU (IFF)
        self.publicar_identidade()
        return True

    def encerrar(self):
        """Encerra conexão MQTT."""
        self.mqtt.desconectar()

    # ─────────────────────────────────────────────
    #  Identidade (IFF)
    # ─────────────────────────────────────────────

    def publicar_identidade(self) -> bool:
        """Publica chaves públicas no CCU para outras UTs."""
        chaves = self.gerenciador.obter_chaves_publicas_b64()
        resultado = self.mqtt.publicar_identidade(
            chaves["rsa_publica"],
            chaves["ecdsa_publica"],
        )
        if resultado:
            logger.info(f"📰 Identidade publicada: sisdef/broadcast/chaves/{self.id_unidade}")
        return resultado

    # ─────────────────────────────────────────────
    #  Envio de Mensagens
    # ─────────────────────────────────────────────

    def enviar_mensagem(self, destinatario: str, conteudo: str) -> bool:
        """
        Envia mensagem segura para outra UT.

        Requisitos:
          - Chave pública RSA do destinatário deve estar registrada
          - Mensagem será cifrada com AES-256-GCM e assinada com ECDSA
        """
        destinatario = destinatario.lower()

        if self.gerenciador.esta_revogada(destinatario):
            logger.error(f"⛔ Tentativa de enviar mensagem para unidade revogada: {destinatario}")
            return False

        chave_rsa_dest = self.gerenciador.obter_chave_publica_rsa(destinatario)
        if chave_rsa_dest is None:
            logger.error(f"❌ Chave RSA de '{destinatario}' não encontrada. "
                         f"A unidade já publicou identidade?")
            return False

        try:
            payload_json = empacotar_mensagem(
                plaintext=conteudo,
                chave_publica_rsa_destinatario=chave_rsa_dest,
                chave_privada_ecdsa_remetente=self.gerenciador.chave_privada_ecdsa,
                id_remetente=self.id_unidade,
            )
        except Exception as e:
            logger.error(f"❌ Erro ao empacotar mensagem: {e}")
            return False

        resultado = self.mqtt.enviar_mensagem(destinatario, payload_json)
        if resultado:
            self._log(f"📤 Mensagem enviada para {destinatario}: {conteudo[:50]}...")
        return resultado

    # ─────────────────────────────────────────────
    #  Recepção de Mensagens (callbacks MQTT)
    # ─────────────────────────────────────────────

    def _processar_mensagem_recebida(self, topico: str, payload_str: str):
        """Processa e valida mensagem segura recebida."""
        logger.info(f"\n{'─'*50}")
        logger.info(f"📨 Mensagem recebida no tópico: {topico}")

        # Tenta verificar o remetente antes de processar (para checar revogação)
        try:
            dados_brutos = json.loads(payload_str)
            id_remetente_alegado = dados_brutos.get("id_unidade", "").lower()
        except Exception:
            id_remetente_alegado = "desconhecido"

        if self.gerenciador.esta_revogada(id_remetente_alegado):
            self._log(f"⛔ BLOQUEADO: Mensagem de unidade revogada '{id_remetente_alegado}'")
            logger.warning(f"⛔ Mensagem de unidade revogada '{id_remetente_alegado}' DESCARTADA.")
            return

        resultado = desempacotar_mensagem(
            payload_json=payload_str,
            chave_privada_rsa_receptor=self.gerenciador.chave_privada_rsa,
            obter_chave_publica_ecdsa=self.gerenciador.obter_chave_publica_ecdsa,
        )

        if resultado["sucesso"]:
            remetente = resultado["id_remetente"]
            mensagem = resultado["mensagem"]
            logger.info(f"✅ Mensagem AUTÊNTICA e ÍNTEGRA de '{remetente}':")
            logger.info(f"   📜 Conteúdo: {mensagem}")
            self._log(f"✅ Recebida de {remetente}: {mensagem[:80]}")
        else:
            erro = resultado.get("erro", "Erro desconhecido")
            remetente = resultado.get("id_remetente", "desconhecido")
            logger.error(f"❌ Falha na validação da mensagem de '{remetente}': {erro}")
            self._log(f"❌ FALHA de {remetente}: {erro}")

            # Reporta ao Oráculo se a validação falhar
            self._reportar_falha_oraculo(remetente, erro)

        logger.info(f"{'─'*50}\n")

    def _processar_chaves_recebidas(self, id_origem: str, dados: dict):
        """Processa publicação de identidade de outra UT."""
        rsa_b64 = dados.get("chave_publica_rsa")
        ecdsa_b64 = dados.get("chave_publica_eddsa")  # campo do protocolo

        if not rsa_b64 or not ecdsa_b64:
            logger.warning(f"⚠️  Chaves de '{id_origem}' malformadas (campos ausentes).")
            return

        self.gerenciador.adicionar_chave_confiavel(id_origem, rsa_b64, ecdsa_b64)
        logger.info(f"🔑 Chaves de '{id_origem}' registradas com sucesso.")

    def _processar_revogacao_recebida(self, payload_str: str):
        """Processa e aplica ordem de revogação."""
        logger.info(f"\n{'═'*50}")
        logger.info(f"🚨 ORDEM DE REVOGAÇÃO RECEBIDA")

        resultado = validar_pacote_revogacao(
            payload_json=payload_str,
            obter_chave_publica_ecdsa=self.gerenciador.obter_chave_publica_ecdsa,
        )

        if resultado["sucesso"]:
            remetente = resultado["remetente"]
            unidade_revogada = resultado["unidade_revogada"]
            timestamp = resultado.get("timestamp", "desconhecido")

            logger.warning(
                f"✅ Revogação VÁLIDA emitida por '{remetente}': "
                f"unidade '{unidade_revogada}' revogada em {timestamp}"
            )
            self.gerenciador.revogar_unidade(unidade_revogada)
            self._log(f"🚫 REVOGAÇÃO aplicada: {unidade_revogada} por {remetente}")
        else:
            erro = resultado.get("erro", "Erro desconhecido")
            remetente = resultado.get("remetente", "desconhecido")
            logger.error(f"❌ Revogação INVÁLIDA de '{remetente}': {erro}")
            self._log(f"❌ REVOGAÇÃO FALSA detectada de {remetente}: {erro}")

        logger.info(f"{'═'*50}\n")

    # ─────────────────────────────────────────────
    #  Revogação de Unidades
    # ─────────────────────────────────────────────

    def revogar_unidade(self, id_unidade: str) -> bool:
        """
        Emite e publica ordem de revogação de uma unidade comprometida.
        """
        id_unidade = id_unidade.lower()
        try:
            pacote_json = criar_pacote_revogacao(
                id_remetente=self.id_unidade,
                unidade_revogada=id_unidade,
                chave_privada_ecdsa_remetente=self.gerenciador.chave_privada_ecdsa,
            )
        except Exception as e:
            logger.error(f"❌ Erro ao criar pacote de revogação: {e}")
            return False

        # Aplica localmente antes de publicar
        self.gerenciador.revogar_unidade(id_unidade)

        resultado = self.mqtt.publicar_revogacao(pacote_json)
        if resultado:
            logger.warning(f"🚫 Ordem de revogação publicada para: {id_unidade}")
            self._log(f"🚫 Revogação emitida: {id_unidade}")
        return resultado

    # ─────────────────────────────────────────────
    #  Interação com o Oráculo
    # ─────────────────────────────────────────────

    def enviar_eco_oraculo(self) -> bool:
        """
        Envia comando 'echo' ao Oráculo para testar o canal.
        A resposta será processada automaticamente pelo callback de mensagem.
        """
        return self.mqtt.enviar_eco_oraculo()

    def _reportar_falha_oraculo(self, remetente: str, erro: str):
        """Reporta falha de validação ao Oráculo (mensagem cifrada)."""
        try:
            conteudo = json.dumps({
                "tipo": "ALERTA_SEGURANCA",
                "remetente_suspeito": remetente,
                "descricao": erro,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            })
            self.enviar_mensagem("oraculo", conteudo)
            logger.info("📡 Falha reportada ao Oráculo.")
        except Exception as e:
            logger.error(f"❌ Não foi possível reportar ao Oráculo: {e}")

    # ─────────────────────────────────────────────
    #  Consultas e Status
    # ─────────────────────────────────────────────

    def listar_chaves_confiaveis(self) -> dict:
        """Lista todas as unidades com chaves registradas e não revogadas."""
        return self.gerenciador.listar_chaves_confiaveis()

    def status_conexao_mqtt(self) -> dict:
        """Retorna status atual da conexão MQTT."""
        return self.mqtt.status_conexao()

    def obter_log_seguranca(self) -> list:
        """Retorna log de eventos de segurança."""
        return self._log_seguranca.copy()

    def _log(self, msg: str):
        """Registra evento de segurança com timestamp."""
        entrada = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "evento": msg,
        }
        self._log_seguranca.append(entrada)
        # Mantém apenas os últimos 100 eventos
        if len(self._log_seguranca) > 100:
            self._log_seguranca = self._log_seguranca[-100:]
