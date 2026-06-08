"""
Operação Cripto-Sentinela — UT-Bravo
Interface de linha de comando interativa.

Uso:
    python main.py
"""

import logging
import os
import sys
import time

# ─────────────────────────────────────────────
#  Configuração de Logging
# ─────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("ut_bravo_operacao.log", encoding="utf-8"),
    ],
)

# Reduz verbosidade de bibliotecas externas
logging.getLogger("paho").setLevel(logging.WARNING)

from unidade_tatica import UnidadeTatica

BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║          🛡️  OPERAÇÃO CRIPTO-SENTINELA — UT-BRAVO  🛡️       ║
║         Comando de Defesa Cibernética (CDCiber)             ║
╚══════════════════════════════════════════════════════════════╝
"""

AJUDA = """
┌─────────────────────────────────────────────────────────────┐
│                    COMANDOS DISPONÍVEIS                     │
├────────────────────────┬────────────────────────────────────┤
│ id / identidade        │ Publica identidade no CCU (IFF)    │
│ enviar <UT> <msg>      │ Envia mensagem segura              │
│ eco                    │ Envia eco ao Oráculo               │
│ desafio                │ Solicita desafio ao Oráculo        │
│ resposta <numero>      │ Envia resposta ao desafio          │
│ pergunta               │ Mostra última pergunta recebida    │
│ notas                  │ Atualiza/mostra placar do Oráculo  │
│ revogar <UT>           │ Revoga unidade comprometida        │
│ chaves                 │ Lista UTs com chaves registradas   │
│ revogadas              │ Lista unidades revogadas           │
│ status                 │ Status da conexão MQTT             │
│ log                    │ Log de eventos de segurança        │
│ ajuda / help           │ Exibe este menu                    │
│ sair / exit            │ Encerra a unidade tática           │
└────────────────────────┴────────────────────────────────────┘
Exemplo: enviar ut-alfa Atacar coordenada 22°54'S 43°10'W
"""


def formatar_chaves(chaves: dict) -> str:
    if not chaves:
        return "  (nenhuma UT registrada)"
    linhas = []
    for ut, dados in chaves.items():
        linhas.append(f"  🔑 {ut}")
        linhas.append(f"     Atualizado: {dados.get('ultima_atualizacao', 'desconhecido')}")
    return "\n".join(linhas)


def formatar_log(log: list) -> str:
    if not log:
        return "  (log vazio)"
    linhas = []
    for entrada in log[-15:]:  # Últimas 15 entradas
        linhas.append(f"  [{entrada['timestamp']}] {entrada['evento']}")
    return "\n".join(linhas)


def main():
    print(BANNER)

    # Muda para o diretório do script para garantir paths corretos
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    print("🔧 Iniciando UT-Bravo...")
    ut = UnidadeTatica()

    print("🔗 Conectando ao Canal de Comando Unificado (CCU)...")
    if not ut.iniciar():
        print("❌ Falha ao conectar ao CCU. Verifique sua conexão com a internet.")
        sys.exit(1)

    print(f"\n✅ UT-Bravo operacional! ID: ut-bravo")
    print(AJUDA)

    # Loop interativo
    try:
        while True:
            try:
                entrada = input("UT-Bravo> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n\n⚡ Encerrando operação...")
                break

            if not entrada:
                continue

            partes = entrada.split(maxsplit=2)
            cmd = partes[0].lower()

            # ── identidade ──────────────────────────
            if cmd in ("id", "identidade"):
                print("📰 Publicando identidade no CCU...")
                if ut.publicar_identidade():
                    print("✅ Identidade publicada!")
                else:
                    print("❌ Falha ao publicar identidade.")

            # ── enviar ──────────────────────────────
            elif cmd == "enviar":
                if len(partes) < 3:
                    print("❌ Uso: enviar <id_destinatario> <mensagem>")
                    continue
                destinatario = partes[1]
                mensagem = partes[2]
                print(f"📤 Enviando mensagem para {destinatario}...")
                if ut.enviar_mensagem(destinatario, mensagem):
                    print(f"✅ Mensagem enviada para {destinatario}!")
                else:
                    print(f"❌ Falha ao enviar mensagem para {destinatario}.")

            # ── eco (oráculo) ────────────────────────
            elif cmd == "eco":
                print("📡 Enviando eco ao Oráculo...")
                if ut.enviar_eco_oraculo():
                    print("✅ Eco enviado! Aguarde resposta no canal direto...")
                else:
                    print("❌ Falha ao enviar eco.")

            # ── desafio (oráculo) ────────────────────
            elif cmd == "desafio":
                print("📡 Solicitando desafio ao Oráculo...")
                if ut.solicitar_desafio_oraculo():
                    print("✅ Desafio solicitado! Aguarde a pergunta no canal direto...")
                else:
                    print("❌ Falha ao solicitar desafio.")

            # ── resposta (oráculo) ────────────────────
            elif cmd == "resposta":
                if len(partes) < 2:
                    print("❌ Uso: resposta <numero>")
                    continue
                resposta = entrada.split(maxsplit=1)[1].strip()
                print("📤 Enviando resposta ao Oráculo...")
                if ut.responder_desafio_oraculo(resposta):
                    print("✅ Resposta enviada ao Oráculo!")
                else:
                    print("❌ Falha ao enviar resposta.")

            # ── pergunta recebida ─────────────────────
            elif cmd == "pergunta":
                pergunta = ut.obter_ultima_pergunta_oraculo()
                if pergunta:
                    print(f"\n📜 Última pergunta do Oráculo:\n  {pergunta}\n")
                else:
                    print("ℹ️  Nenhuma pergunta do Oráculo foi decifrada ainda.")

            # ── notas (oráculo) ───────────────────────
            elif cmd == "notas":
                print("📊 Solicitando atualização do placar...")
                if ut.atualizar_notas_oraculo():
                    print("✅ Solicitação enviada. Aguarde o placar no tópico público...")
                    time.sleep(1)
                else:
                    print("❌ Falha ao solicitar notas.")
                placar = ut.obter_ultimo_placar()
                if placar:
                    print(f"\n📊 Último placar recebido:\n{placar}\n")

            # ── revogar ─────────────────────────────
            elif cmd == "revogar":
                if len(partes) < 2:
                    print("❌ Uso: revogar <id_unidade>")
                    continue
                alvo = partes[1]
                confirma = input(f"⚠️  Confirmar revogação de '{alvo}'? (s/N): ").strip().lower()
                if confirma == "s":
                    if ut.revogar_unidade(alvo):
                        print(f"🚫 Ordem de revogação emitida para {alvo}!")
                    else:
                        print(f"❌ Falha ao revogar {alvo}.")
                else:
                    print("↩️  Revogação cancelada.")

            # ── listar chaves ────────────────────────
            elif cmd == "chaves":
                chaves = ut.listar_chaves_confiaveis()
                print(f"\n📋 UTs com chaves registradas ({len(chaves)}):")
                print(formatar_chaves(chaves))
                print()

            # ── listar revogadas ─────────────────────
            elif cmd == "revogadas":
                revogadas = ut.gerenciador.listar_revogadas()
                if revogadas:
                    print(f"\n🚫 Unidades revogadas ({len(revogadas)}):")
                    for ut_rev in revogadas:
                        print(f"  ⛔ {ut_rev}")
                else:
                    print("✅ Nenhuma unidade revogada.")
                print()

            # ── status ───────────────────────────────
            elif cmd == "status":
                status = ut.status_conexao_mqtt()
                print(f"\n📡 Status da Conexão MQTT:")
                print(f"  Conectado : {'✅ Sim' if status['conectado'] else '❌ Não'}")
                print(f"  Broker    : {status['broker']}:{status['porta']}")
                print(f"  Unidade   : {status['id_unidade']}")
                print()

            # ── log ──────────────────────────────────
            elif cmd == "log":
                log = ut.obter_log_seguranca()
                print(f"\n📋 Log de Segurança (últimos {min(15, len(log))} eventos):")
                print(formatar_log(log))
                print()

            # ── ajuda ────────────────────────────────
            elif cmd in ("ajuda", "help", "h", "?"):
                print(AJUDA)

            # ── sair ─────────────────────────────────
            elif cmd in ("sair", "exit", "quit", "q"):
                print("⚡ Encerrando operação...")
                break

            else:
                print(f"❓ Comando desconhecido: '{cmd}'. Digite 'ajuda' para ver os comandos.")

    finally:
        ut.encerrar()
        print("\n🏁 UT-Bravo desconectada. Missão encerrada.")


if __name__ == "__main__":
    main()
