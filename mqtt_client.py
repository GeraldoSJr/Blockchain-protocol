"""
Operação Cripto-Sentinela — UT-Bravo
Cliente MQTT: publicação e recepção de mensagens via broker HiveMQ.
"""

import json
import logging
import threading
import time
from typing import Callable, Optional

import paho.mqtt.client as mqtt

logger = logging.getLogger("UT-Bravo.MQTT")

BROKER = "broker.hivemq.com"
PORT = 1883

# Tópicos padrão do protocolo Cripto-Sentinela
TOPICO_CHAVES_BASE = "sisdef/broadcast/chaves"
TOPICO_DIRETO_BASE = "sisdef/direto"
TOPICO_REVOGACAO = "sisdef/broadcast/revogacao"
TOPICO_NOTAS = "sisdef/broadcast/notas"


class ClienteMQTT:
    """
    Gerencia a conexão MQTT da UT-Bravo com o Canal de Comando Unificado (CCU).
    """

    def __init__(self, id_unidade: str):
        self.id_unidade = id_unidade.lower()
        self.client = mqtt.Client(client_id=f"cripto-sentinela-{self.id_unidade}-{int(time.time())}")
        self.conectado = False
        self._lock = threading.Lock()

        # Callbacks externos injetados pela UnidadeTatica
        self.on_mensagem_recebida: Optional[Callable[[str, str], None]] = None
        self.on_chaves_recebidas: Optional[Callable[[str, dict], None]] = None
        self.on_revogacao_recebida: Optional[Callable[[str], None]] = None
        self.on_notas_recebidas: Optional[Callable[[str], None]] = None

        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_message = self._on_message

    # ─────────────────────────────────────────────
    #  Conexão
    # ─────────────────────────────────────────────

    def conectar(self, timeout: int = 10) -> bool:
        """Conecta ao broker MQTT. Retorna True se bem-sucedido."""
        logger.info(f"🔗 Conectando ao broker {BROKER}:{PORT}...")
        try:
            self.client.connect(BROKER, PORT, keepalive=60)
            self.client.loop_start()

            # Aguarda conexão
            deadline = time.time() + timeout
            while not self.conectado and time.time() < deadline:
                time.sleep(0.1)

            if self.conectado:
                self._inscrever_topicos()
                logger.info("✅ Conectado ao CCU!")
                return True
            else:
                logger.error("❌ Timeout na conexão MQTT.")
                return False
        except Exception as e:
            logger.error(f"❌ Erro na conexão MQTT: {e}")
            return False

    def desconectar(self):
        """Encerra a conexão MQTT graciosamente."""
        self.client.loop_stop()
        self.client.disconnect()
        logger.info("🔌 Desconectado do CCU.")

    def status_conexao(self) -> dict:
        return {
            "conectado": self.conectado,
            "broker": BROKER,
            "porta": PORT,
            "id_unidade": self.id_unidade,
        }

    # ─────────────────────────────────────────────
    #  Inscrições em Tópicos
    # ─────────────────────────────────────────────

    def _inscrever_topicos(self):
        """Inscreve nos tópicos relevantes após conexão."""
        # Mensagens diretas para nós
        topico_direto = f"{TOPICO_DIRETO_BASE}/{self.id_unidade}"
        self.client.subscribe(topico_direto)
        logger.info(f"📥 Inscrito: {topico_direto}")

        # Broadcast de chaves de todas as UTs
        topico_chaves = f"{TOPICO_CHAVES_BASE}/#"
        self.client.subscribe(topico_chaves)
        logger.info(f"📥 Inscrito: {topico_chaves}")

        # Revogações
        self.client.subscribe(TOPICO_REVOGACAO)
        logger.info(f"📥 Inscrito: {TOPICO_REVOGACAO}")

        # Placar do Oráculo
        self.client.subscribe(TOPICO_NOTAS)
        logger.info(f"📥 Inscrito: {TOPICO_NOTAS}")

    # ─────────────────────────────────────────────
    #  Publicações
    # ─────────────────────────────────────────────

    def publicar_identidade(self, rsa_publica_b64: str, ecdsa_publica_b64: str) -> bool:
        """
        Publica chaves públicas no tópico de identidade (IFF).
        Tópico: sisdef/broadcast/chaves/<id_unidade>
        """
        payload = json.dumps({
            "id_unidade": self.id_unidade,
            "chave_publica_rsa": rsa_publica_b64,
            "chave_publica_ecdsa": ecdsa_publica_b64,
            "chave_publica_eddsa": ecdsa_publica_b64,
        })
        topico = f"{TOPICO_CHAVES_BASE}/{self.id_unidade}"
        return self._publicar(topico, payload, retain=True)

    def enviar_mensagem(self, id_destinatario: str, payload_json: str) -> bool:
        """
        Envia mensagem cifrada para outra UT.
        Tópico: sisdef/direto/<id_destinatario>
        """
        topico = f"{TOPICO_DIRETO_BASE}/{id_destinatario.lower()}"
        return self._publicar(topico, payload_json)

    def publicar_revogacao(self, pacote_revogacao_json: str) -> bool:
        """
        Publica ordem de revogação no canal de broadcast.
        Tópico: sisdef/broadcast/revogacao
        """
        return self._publicar(TOPICO_REVOGACAO, pacote_revogacao_json)

    def enviar_eco_oraculo(self) -> bool:
        """
        Envia comando 'echo' para o Oráculo para testar o canal.
        """
        payload = json.dumps({
            "id_unidade": self.id_unidade,
            "cmd": "echo",
        })
        topico = f"{TOPICO_DIRETO_BASE}/oraculo"
        logger.info(f"📡 Enviando eco ao Oráculo: {topico}")
        return self._publicar(topico, payload)

    def enviar_desafio_oraculo(self) -> bool:
        """
        Solicita novo desafio ao Oráculo.
        """
        payload = json.dumps({
            "id_unidade": self.id_unidade,
            "cmd": "desafio",
        })
        topico = f"{TOPICO_DIRETO_BASE}/oraculo"
        logger.info(f"📡 Solicitando desafio ao Oráculo: {topico}")
        return self._publicar(topico, payload)

    def atualizar_notas_oraculo(self) -> bool:
        """
        Solicita atualização do placar público mantido pelo Oráculo.
        """
        payload = json.dumps({"cmd": "atualizar_notas"})
        logger.info(f"📊 Solicitando atualização de notas: {TOPICO_NOTAS}")
        return self._publicar(TOPICO_NOTAS, payload)

    def _publicar(self, topico: str, payload: str, retain: bool = False) -> bool:
        if not self.conectado:
            logger.error("❌ Não conectado ao broker MQTT.")
            return False
        try:
            result = self.client.publish(topico, payload, qos=1, retain=retain)
            result.wait_for_publish(timeout=5)
            logger.info(f"📤 Publicado em '{topico}': {payload[:80]}{'...' if len(payload) > 80 else ''}")
            return True
        except Exception as e:
            logger.error(f"❌ Falha ao publicar em '{topico}': {e}")
            return False

    # ─────────────────────────────────────────────
    #  Callbacks MQTT
    # ─────────────────────────────────────────────

    def _on_connect(self, client, userdata, flags, rc):
        codigos = {
            0: "Conexão aceita",
            1: "Versão de protocolo inaceitável",
            2: "Identificador rejeitado",
            3: "Servidor indisponível",
            4: "Usuário/senha incorretos",
            5: "Não autorizado",
        }
        if rc == 0:
            self.conectado = True
            logger.info(f"✅ Conectado: {codigos.get(rc, f'Código {rc}')}")
        else:
            self.conectado = False
            logger.error(f"❌ Falha na conexão: {codigos.get(rc, f'Código {rc}')}")

    def _on_disconnect(self, client, userdata, rc):
        self.conectado = False
        if rc != 0:
            logger.warning(f"⚠️  Desconexão inesperada (rc={rc}). Reconectando...")

    def _on_message(self, client, userdata, msg):
        topico = msg.topic
        try:
            payload_str = msg.payload.decode("utf-8")
        except Exception as e:
            logger.error(f"❌ Erro ao decodificar payload de '{topico}': {e}")
            return

        logger.debug(f"📨 Mensagem recebida em '{topico}': {payload_str[:100]}...")

        # Despacha para o callback correto
        if topico.startswith(f"{TOPICO_CHAVES_BASE}/"):
            id_origem = topico.split("/")[-1]
            if id_origem != self.id_unidade:  # Ignora as próprias chaves
                if self.on_chaves_recebidas:
                    try:
                        dados = json.loads(payload_str)
                        self.on_chaves_recebidas(id_origem, dados)
                    except json.JSONDecodeError as e:
                        logger.error(f"❌ JSON inválido no tópico de chaves '{topico}': {e}")

        elif topico == TOPICO_REVOGACAO:
            if self.on_revogacao_recebida:
                self.on_revogacao_recebida(payload_str)

        elif topico == TOPICO_NOTAS:
            if self.on_notas_recebidas:
                self.on_notas_recebidas(payload_str)

        elif topico == f"{TOPICO_DIRETO_BASE}/{self.id_unidade}":
            if self.on_mensagem_recebida:
                self.on_mensagem_recebida(topico, payload_str)

        else:
            logger.debug(f"🔕 Tópico ignorado: {topico}")
