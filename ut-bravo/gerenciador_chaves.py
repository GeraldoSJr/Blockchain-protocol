"""
Operação Cripto-Sentinela — UT-Bravo
Gerenciador de Chaves: persistência local, carregamento e revogação.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from crypto import (
    carregar_chave_publica_ecdsa,
    carregar_chave_publica_rsa,
    carregar_chave_privada_ecdsa,
    carregar_chave_privada_rsa,
    exportar_chaves_b64,
    gerar_chaves_ecdsa,
    gerar_chaves_rsa,
)

logger = logging.getLogger("UT-Bravo.GerenciadorChaves")

ARQUIVO_CHAVES_CONFIAVEIS = "chaves_confiaveis.json"
ARQUIVO_MINHAS_CHAVES = "minhas_chaves.json"
ARQUIVO_REVOGADAS = "unidades_revogadas.json"


class GerenciadorChaves:
    """
    Centraliza toda a gestão de chaves da UT-Bravo:
      - Geração e persistência das próprias chaves
      - Armazenamento de chaves públicas de outras UTs
      - Controle de revogações
    """

    def __init__(self):
        self.chave_privada_rsa = None
        self.chave_publica_rsa = None
        self.chave_privada_ecdsa = None
        self.chave_publica_ecdsa = None

        # {id_unidade: {"chave_publica_rsa": str_b64, "chave_publica_ecdsa": str_b64, "ultima_atualizacao": str}}
        self.chaves_confiaveis: dict = {}

        # set de ids revogados
        self.unidades_revogadas: set = set()

        self._carregar_ou_gerar_chaves_proprias()
        self._carregar_chaves_confiaveis()
        self._carregar_revogacoes()

    # ─────────────────────────────────────────────
    #  Chaves Próprias
    # ─────────────────────────────────────────────

    def _carregar_ou_gerar_chaves_proprias(self):
        """Carrega chaves do disco, ou gera e salva novas se não existirem."""
        if os.path.exists(ARQUIVO_MINHAS_CHAVES):
            try:
                with open(ARQUIVO_MINHAS_CHAVES, "r") as f:
                    dados = json.load(f)
                self.chave_privada_rsa = carregar_chave_privada_rsa(dados["rsa_privada"])
                self.chave_publica_rsa = carregar_chave_publica_rsa(dados["rsa_publica"])
                self.chave_privada_ecdsa = carregar_chave_privada_ecdsa(dados["ecdsa_privada"])
                self.chave_publica_ecdsa = carregar_chave_publica_ecdsa(dados["ecdsa_publica"])
                logger.info("✅ Chaves próprias carregadas do disco.")
                return
            except Exception as e:
                logger.warning(f"⚠️  Falha ao carregar chaves do disco: {e}. Gerando novas chaves...")

        # Gera novas chaves
        self.chave_privada_rsa, self.chave_publica_rsa = gerar_chaves_rsa()
        self.chave_privada_ecdsa, self.chave_publica_ecdsa = gerar_chaves_ecdsa()

        rsa_b64 = exportar_chaves_b64(self.chave_privada_rsa, self.chave_publica_rsa)
        ecdsa_b64 = exportar_chaves_b64(self.chave_privada_ecdsa, self.chave_publica_ecdsa)

        dados = {
            "rsa_publica": rsa_b64["public_key"],
            "rsa_privada": rsa_b64["private_key"],
            "ecdsa_publica": ecdsa_b64["public_key"],
            "ecdsa_privada": ecdsa_b64["private_key"],
        }

        with open(ARQUIVO_MINHAS_CHAVES, "w") as f:
            json.dump(dados, f, indent=2)

        logger.info("🔑 Novas chaves geradas e salvas em disco.")

    def obter_chaves_publicas_b64(self) -> dict:
        """Retorna chaves públicas próprias em Base64 (para publicar no MQTT)."""
        rsa_b64 = exportar_chaves_b64(self.chave_privada_rsa, self.chave_publica_rsa)
        ecdsa_b64 = exportar_chaves_b64(self.chave_privada_ecdsa, self.chave_publica_ecdsa)
        return {
            "rsa_publica": rsa_b64["public_key"],
            "ecdsa_publica": ecdsa_b64["public_key"],
        }

    # ─────────────────────────────────────────────
    #  Chaves de Outras UTs
    # ─────────────────────────────────────────────

    def _carregar_chaves_confiaveis(self):
        if os.path.exists(ARQUIVO_CHAVES_CONFIAVEIS):
            try:
                with open(ARQUIVO_CHAVES_CONFIAVEIS, "r") as f:
                    self.chaves_confiaveis = json.load(f)
                logger.info(f"📂 Chaves confiáveis carregadas: {list(self.chaves_confiaveis.keys())}")
            except Exception as e:
                logger.warning(f"⚠️  Falha ao carregar chaves confiáveis: {e}")
                self.chaves_confiaveis = {}
        else:
            self.chaves_confiaveis = {}

    def _salvar_chaves_confiaveis(self):
        with open(ARQUIVO_CHAVES_CONFIAVEIS, "w") as f:
            json.dump(self.chaves_confiaveis, f, indent=2)

    def adicionar_chave_confiavel(self, id_unidade: str, rsa_publica_b64: str, ecdsa_publica_b64: str):
        """Adiciona ou atualiza chave de uma unidade confiável."""
        if id_unidade in self.unidades_revogadas:
            logger.warning(f"⛔ Tentativa de adicionar chave de unidade revogada: {id_unidade}")
            return

        self.chaves_confiaveis[id_unidade] = {
            "chave_publica_rsa": rsa_publica_b64,
            "chave_publica_ecdsa": ecdsa_publica_b64,
            "ultima_atualizacao": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        self._salvar_chaves_confiaveis()
        logger.info(f"✅ Chaves de {id_unidade} adicionadas/atualizadas.")

    def obter_chave_publica_rsa(self, id_unidade: str):
        """Retorna objeto de chave pública RSA ou None se não encontrada/revogada."""
        if id_unidade in self.unidades_revogadas:
            logger.warning(f"⛔ Unidade revogada: {id_unidade}")
            return None
        entrada = self.chaves_confiaveis.get(id_unidade)
        if not entrada:
            return None
        try:
            return carregar_chave_publica_rsa(entrada["chave_publica_rsa"])
        except Exception as e:
            logger.error(f"❌ Erro ao carregar RSA de {id_unidade}: {e}")
            return None

    def obter_chave_publica_ecdsa(self, id_unidade: str):
        """Retorna objeto de chave pública ECDSA ou None se não encontrada/revogada."""
        if id_unidade in self.unidades_revogadas:
            logger.warning(f"⛔ Unidade revogada: {id_unidade}")
            return None
        entrada = self.chaves_confiaveis.get(id_unidade)
        if not entrada:
            return None
        try:
            return carregar_chave_publica_ecdsa(entrada["chave_publica_ecdsa"])
        except Exception as e:
            logger.error(f"❌ Erro ao carregar ECDSA de {id_unidade}: {e}")
            return None

    def listar_chaves_confiaveis(self) -> dict:
        """Lista todas as unidades com chaves armazenadas (exceto revogadas)."""
        return {
            uid: dados
            for uid, dados in self.chaves_confiaveis.items()
            if uid not in self.unidades_revogadas
        }

    # ─────────────────────────────────────────────
    #  Revogação
    # ─────────────────────────────────────────────

    def _carregar_revogacoes(self):
        if os.path.exists(ARQUIVO_REVOGADAS):
            try:
                with open(ARQUIVO_REVOGADAS, "r") as f:
                    dados = json.load(f)
                self.unidades_revogadas = set(dados.get("revogadas", []))
                logger.info(f"🚫 Unidades revogadas carregadas: {self.unidades_revogadas}")
            except Exception as e:
                logger.warning(f"⚠️  Falha ao carregar revogações: {e}")
                self.unidades_revogadas = set()
        else:
            self.unidades_revogadas = set()

    def _salvar_revogacoes(self):
        with open(ARQUIVO_REVOGADAS, "w") as f:
            json.dump({"revogadas": list(self.unidades_revogadas)}, f, indent=2)

    def revogar_unidade(self, id_unidade: str):
        """Adiciona unidade à lista de revogação e remove suas chaves."""
        self.unidades_revogadas.add(id_unidade)
        # Remove completamente da lista de confiança
        if id_unidade in self.chaves_confiaveis:
            del self.chaves_confiaveis[id_unidade]
            self._salvar_chaves_confiaveis()
        self._salvar_revogacoes()
        logger.warning(f"🚫 Unidade {id_unidade} REVOGADA. Comunicações futuras serão bloqueadas.")

    def esta_revogada(self, id_unidade: str) -> bool:
        return id_unidade in self.unidades_revogadas

    def listar_revogadas(self) -> list:
        return list(self.unidades_revogadas)
