#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sonda_medicion.py - Medicion activa no invasiva (Proyecto NetDiag-Macas)
Actividad de Avance: validacion del script en el laboratorio de la Sede Riobamba.

Que hace
--------
En cada ciclo ejecuta, hacia destinos institucionales y externos:
  ping (RTT min/mediana/prom/max, jitter, perdida) | traceroute (saltos) |
  dig (tiempo DNS) | iperf3 TCP y UDP (Mbps, retransmisiones, jitter, perdida).
Los ciclos se programan a intervalos fijos (por defecto 5 ciclos cada 15 min = 1 h+).

Lo que NO hace
--------------
No captura paquetes (no usa dumpcap/tcpdump), no usa SPAN y solo genera trafico propio.

Salida (carpeta --outdir)
-------------------------
  run.json         : sesion (inicio/fin, hostname, IP, interfaz, versiones, config, verificacion)
  mediciones.csv   : formato largo (una fila por metrica) con timestamp, dominio, destino...
  mediciones.json  : las mismas filas en JSON
  resumen.csv      : n, min, mediana y max por destino/herramienta/metrica (base de la tabla E3)
  sesion.log       : copia de lo impreso en consola (evidencia E4)

Requisitos: Python 3.8+ (solo biblioteca estandar) y las herramientas ping, traceroute,
dig (dnsutils) e iperf3.
"""

import argparse
import csv
import getpass
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone

# =============================================================================
# 1. CONFIGURACION (se puede sobrescribir parcialmente con --config archivo.json)
# =============================================================================
DEFAULT_CONFIG = {
    "probe_id": "PROBE-RIOBAMBA-LAB",
    "ping": {"count": 10, "interval_s": 1.0, "wait_s": 2},
    # Destinos de ping y traceroute
    "destinos": [
        {"nombre": "srv_referencia", "dominio": "institucional", "host": "172.17.103.102"},
        {"nombre": "dns1_espoch", "dominio": "institucional", "host": "172.17.102.39"},
        {"nombre": "google_dns", "dominio": "externo", "host": "8.8.8.8"},
        {"nombre": "cloudflare", "dominio": "externo", "host": "1.1.1.1"},
    ],
    "traceroute": {"max_hops": 20, "wait_s": 1, "icmp": "auto"},   # icmp: auto|si|no
    "dns": {
        "name": "espoch.edu.ec",
        "servers": [
            {"nombre": "dns1_espoch", "dominio": "institucional", "host": "172.17.102.39"},
            {"nombre": "dns2_espoch", "dominio": "institucional", "host": "172.17.102.40"},
            {"nombre": "google_dns", "dominio": "externo", "host": "8.8.8.8"},
        ],
    },
    "iperf": {
        "duracion_s": 10,            # rafagas breves (ficha DTIC: 10-15 s)
        "udp_bitrate": "50M",
        "reverse": False,            # True agrega una prueba TCP de descarga (-R)
        "precheck_timeout_s": 3,     # prueba rapida de conexion TCP al puerto antes de iperf3
        "destinos": [
            {"nombre": "srv_referencia", "dominio": "institucional",
             "host": "172.17.103.102", "port": 5201, "extra": []},
            # AJUSTAR: servidor externo autorizado que responda desde la red de la sede
            {"nombre": "speedtest_masnet", "dominio": "externo",
             "host": "speedtest.masnet.ec", "port": 5201, "extra": ["-4"]},
        ],
    },
    "ciclos": 5,
    "periodo_s": 900,                # 15 min entre inicios de ciclo -> 5 ciclos = 1 h
    "output_dir": "salida_lab",
}

CSV_COLS = ["ts_utc", "ts_local", "ciclo", "dominio", "destino", "herramienta",
            "metrica", "valor", "unidad", "estado", "detalle"]

# =============================================================================
# 2. UTILIDADES
# =============================================================================
RE_PING_SUM = re.compile(r"(\d+) packets transmitted, (\d+) (?:packets )?received")
RE_PING_RTT = re.compile(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms")
RE_PING_T = re.compile(r"time[=<]([\d.]+)\s*ms")
RE_DIG_TIME = re.compile(r";; Query time: (\d+) msec")
RE_DIG_STATUS = re.compile(r"status: (\w+)")
RE_DIG_A = re.compile(r"^\S+\s+\d+\s+IN\s+A\s+(\S+)", re.M)

def utc_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def local_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")

def run_cmd(cmd, timeout, solo_stdout=False):
    """Ejecuta un comando externo con locale C. Devuelve (codigo, salida)."""
    env = dict(os.environ, LC_ALL="C")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return p.returncode, (p.stdout if solo_stdout else p.stdout + p.stderr)
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except FileNotFoundError:
        return 127, "comando no encontrado: " + cmd

def deep_update(base, new):
    for k, v in new.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            deep_update(base[k], v)
        else:
            base[k] = v

def resolver_ipv4(host):
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None

def puerto_tcp_abierto(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False

class Tee:
    """Duplica la salida de consola en sesion.log (evidencia E4)."""

    def __init__(self, path):
        self.f = open(path, "a", encoding="utf-8")
        self.out = sys.stdout

    def write(self, s):
        self.out.write(s)
        self.f.write(s)
        self.f.flush()

    def flush(self):
        self.out.flush()
        self.f.flush()

# =============================================================================
# 3. REGISTRO DE MEDICIONES
# =============================================================================
class Registro:
    def __init__(self, outdir):
        self.csv_path = os.path.join(outdir, "mediciones.csv")
        self.json_path = os.path.join(outdir, "mediciones.json")
        self.rows = []
        self.fh = open(self.csv_path, "w", newline="", encoding="utf-8")
        self.w = csv.DictWriter(self.fh, fieldnames=CSV_COLS)
        self.w.writeheader()
        self.fh.flush()

    def emit(self, ciclo, dominio, destino, herramienta, metricas, estado, detalle=""):
        """metricas: lista de (nombre, valor, unidad). Valor None -> 'NA'."""
        ts_u, ts_l = utc_iso(), local_iso()
        for nombre, valor, unidad in (metricas or [("-", None, "")]):
            row = {"ts_utc": ts_u, "ts_local": ts_l, "ciclo": ciclo, "dominio": dominio,
                   "destino": destino, "herramienta": herramienta, "metrica": nombre,
                   "valor": "NA" if valor is None else valor, "unidad": unidad,
                   "estado": estado, "detalle": (detalle or "")[:160].replace("\n", " ")}
            self.rows.append(row)
            self.w.writerow(row)
        self.fh.flush()

    def cerrar(self):
        self.fh.close()
        with open(self.json_path, "w", encoding="utf-8") as f:
            json.dump(self.rows, f, indent=1, ensure_ascii=False)

# =============================================================================
# 4. MEDICIONES (cada funcion devuelve (metricas, estado, detalle))
# =============================================================================
def medir_ping(host, cfg):
    p = cfg["ping"]
    n, itv, w = p["count"], p["interval_s"], p["wait_s"]
    nombres = [("perdida_pct", "%"), ("rtt_min_ms", "ms"), ("rtt_mediana_ms", "ms"),
               ("rtt_prom_ms", "ms"), ("rtt_max_ms", "ms"), ("jitter_ms", "ms")]
    vacio = [(k, None, u) for k, u in nombres]
    rc, out = run_cmd(["ping", "-n", "-c", str(n), "-i", str(itv), "-W", str(w), host],
                      n * itv + w + 5)
    if rc == 127:
        return vacio, "HERRAMIENTA_NO_ENCONTRADA", out
    m = RE_PING_SUM.search(out)
    if not m:
        return vacio, "ERROR", out.strip().splitlines()[-1] if out.strip() else "sin salida"
    sent, recv = int(m.group(1)), int(m.group(2))
    loss = round(100.0 * (sent - recv) / sent, 2) if sent else 100.0
    if recv == 0:
        return [("perdida_pct", loss, "%")] + vacio[1:], "SIN_RESPUESTA", "0 respuestas"
    tiempos = [float(x) for x in RE_PING_T.findall(out)]
    r = RE_PING_RTT.search(out)
    rmin, ravg, rmax, jit = (float(x) for x in r.groups()) if r else (
        min(tiempos), statistics.mean(tiempos), max(tiempos),
        statistics.pstdev(tiempos) if len(tiempos) > 1 else 0.0)
    med = round(statistics.median(tiempos), 3) if tiempos else None
    return [("perdida_pct", loss, "%"), ("rtt_min_ms", rmin, "ms"), ("rtt_mediana_ms", med, "ms"),
            ("rtt_prom_ms", ravg, "ms"), ("rtt_max_ms", rmax, "ms"), ("jitter_ms", jit, "ms")], \
        "OK", ""

def traceroute_usa_icmp(cfg):
    modo = cfg["traceroute"]["icmp"]
    if modo == "si":
        return True
    if modo == "no":
        return False
    return hasattr(os, "geteuid") and os.geteuid() == 0     # auto: ICMP solo si es root

def medir_traceroute(host, cfg):
    t = cfg["traceroute"]
    vacio = [("saltos_total", None, "saltos"), ("saltos_sin_respuesta", None, "saltos"),
             ("destino_alcanzado", None, "0/1")]
    cmd = ["traceroute", "-n", "-q", "1", "-w", str(t["wait_s"]), "-m", str(t["max_hops"])]
    if traceroute_usa_icmp(cfg):
        cmd.append("-I")
    rc, out = run_cmd(cmd + [host], t["max_hops"] * (t["wait_s"] + 2) + 10)
    if rc == 127:
        return vacio, "HERRAMIENTA_NO_ENCONTRADA", out
    if "privileges" in out.lower():
        return vacio, "SIN_PRIVILEGIOS", "traceroute -I requiere sudo (o use --traceroute-icmp no)"
    hops = []
    for ln in out.splitlines():
        mm = re.match(r"\s*(\d+)\s+(.*)", ln)
        if mm:
            hops.append((int(mm.group(1)), mm.group(2).strip()))
    if not hops:
        return vacio, "ERROR", out.strip()[:120]
    ip = resolver_ipv4(host)
    ultimo_n, ultimo_txt = hops[-1]
    alcanzado = bool(ip and ip in ultimo_txt)
    sin_resp = sum(1 for _, txt in hops if set(txt.replace(" ", "")) <= {"*"})
    return [("saltos_total", ultimo_n, "saltos"), ("saltos_sin_respuesta", sin_resp, "saltos"),
            ("destino_alcanzado", 1 if alcanzado else 0, "0/1")], \
        ("OK" if alcanzado else "NO_ALCANZADO"), ""

def medir_dns(server, name):
    vacio = [("dns_ms", None, "ms"), ("respuesta_A", None, "ip")]
    rc, out = run_cmd(["dig", "@" + server, name, "A", "+time=3", "+tries=1", "+stats"], 10)
    if rc == 127:
        return vacio, "HERRAMIENTA_NO_ENCONTRADA", out
    t, s = RE_DIG_TIME.search(out), RE_DIG_STATUS.search(out)
    if not (t and s):
        return vacio, "TIMEOUT", out.strip()[:120]
    ips = ";".join(RE_DIG_A.findall(out)) or None
    estado = "OK" if s.group(1) == "NOERROR" else s.group(1)
    return [("dns_ms", float(t.group(1)), "ms"), ("respuesta_A", ips, "ip")], estado, ""

def medir_iperf(dest, cfg, modo):
    """modo: 'tcp' | 'udp' | 'tcp_R'. Devuelve (metricas, estado, detalle)."""
    ip = cfg["iperf"]
    dur = ip["duracion_s"]
    if modo == "udp":
        vacio = [("mbps", None, "Mbps"), ("jitter_ms", None, "ms"),
                 ("perdida_pct", None, "%"), ("paquetes_perdidos", None, "pkts")]
    else:
        vacio = [("mbps_enviado", None, "Mbps"), ("mbps_recibido", None, "Mbps"),
                 ("retransmisiones", None, "pkts")]
    cmd = ["iperf3", "-c", dest["host"], "-p", str(dest["port"]), "-t", str(dur),
           "-J", "--connect-timeout", "3000"] + list(dest.get("extra", []))
    if modo == "udp":
        cmd += ["-u", "-b", ip["udp_bitrate"]]
    elif modo == "tcp_R":
        cmd.append("-R")
    rc, out = run_cmd(cmd, dur + 15, solo_stdout=True)
    if rc == 127:
        return vacio, "HERRAMIENTA_NO_ENCONTRADA", out
    if rc == 124:
        return vacio, "TIMEOUT", "iperf3 no termino en el tiempo esperado"
    try:
        j = json.loads(out)
    except ValueError:
        return vacio, "ERROR", out.strip()[:120] or "sin salida JSON"
    if "error" in j:
        return vacio, "FALLO", str(j["error"])
    end = j.get("end", {})
    if modo == "udp":
        s = end.get("sum", {})
        return [("mbps", round(s.get("bits_per_second", 0) / 1e6, 3), "Mbps"),
                ("jitter_ms", round(s.get("jitter_ms", 0), 3), "ms"),
                ("perdida_pct", round(s.get("lost_percent", 0), 3), "%"),
                ("paquetes_perdidos", s.get("lost_packets"), "pkts")], "OK", ""
    ss, sr = end.get("sum_sent", {}), end.get("sum_received", {})
    return [("mbps_enviado", round(ss.get("bits_per_second", 0) / 1e6, 3), "Mbps"),
            ("mbps_recibido", round(sr.get("bits_per_second", 0) / 1e6, 3), "Mbps"),
            ("retransmisiones", ss.get("retransmits"), "pkts")], "OK", ""

# =============================================================================
# 5. CICLO DE MEDICION
# =============================================================================
def resumen_linea(metricas, estado):
    partes = ["%s=%s" % (k, v) for k, v, _ in metricas[:3] if v is not None]
    return "%-14s %s" % (estado, " ".join(partes))

def ejecutar_ciclo(n, total, cfg, reg, usar_iperf):
    print("\n=== Ciclo %d/%d  %s ===" % (n, total, local_iso()))

    def registrar(dom, dest, herr, res):
        metricas, estado, detalle = res
        reg.emit(n, dom, dest, herr, metricas, estado, detalle)
        print("  %-9s %-13s %-17s %s %s" % (herr, dom, dest, resumen_linea(metricas, estado),
                                            ("(" + detalle[:60] + ")") if detalle else ""))

    for d in cfg["destinos"]:
        registrar(d["dominio"], d["nombre"], "ping", medir_ping(d["host"], cfg))
    for d in cfg["destinos"]:
        registrar(d["dominio"], d["nombre"], "traceroute", medir_traceroute(d["host"], cfg))
    for s in cfg["dns"]["servers"]:
        registrar(s["dominio"], s["nombre"], "dig", medir_dns(s["host"], cfg["dns"]["name"]))
    if not usar_iperf:
        return
    modos = ["tcp", "udp"] + (["tcp_R"] if cfg["iperf"]["reverse"] else [])
    for d in cfg["iperf"]["destinos"]:
        abierto = puerto_tcp_abierto(d["host"], d["port"], cfg["iperf"]["precheck_timeout_s"])
        for modo in modos:
            herr = "iperf3_" + modo
            if not abierto:      # UDP tambien necesita el canal de control TCP
                vacio = medir_iperf_vacio(modo)
                registrar(d["dominio"], d["nombre"], herr,
                          (vacio, "PUERTO_CERRADO", "TCP %d sin respuesta" % d["port"]))
            else:
                registrar(d["dominio"], d["nombre"], herr, medir_iperf(d, cfg, modo))

def medir_iperf_vacio(modo):
    if modo == "udp":
        return [("mbps", None, "Mbps"), ("jitter_ms", None, "ms"),
                ("perdida_pct", None, "%"), ("paquetes_perdidos", None, "pkts")]
    return [("mbps_enviado", None, "Mbps"), ("mbps_recibido", None, "Mbps"),
            ("retransmisiones", None, "pkts")]

# =============================================================================
# 6. INFORMACION DE LA SESION, RESUMEN Y VERIFICACION
# =============================================================================
def info_equipo():
    info = {"hostname": socket.gethostname(), "usuario": getpass.getuser(),
            "sistema": platform.platform(), "python": platform.python_version(),
            "euid": os.geteuid() if hasattr(os, "geteuid") else None,
            "interfaz": None, "ip_sonda": None, "gateway": None, "tipo_enlace": "desconocido",
            "velocidad_mbps": None}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))          # UDP connect: no envia paquetes
        info["ip_sonda"] = s.getsockname()
        s.close()
    except OSError:
        pass
    rc, out = run_cmd(["ip", "-o", "route", "get", "8.8.8.8"], 5)
    if rc == 0:
        for clave, rx in (("interfaz", r"dev (\S+)"), ("gateway", r"via (\S+)"),
                          ("ip_sonda", r"src (\S+)")):
            mm = re.search(rx, out)
            if mm:
                info[clave] = mm.group(1)
    ifc = info["interfaz"]
    if ifc and os.path.isdir("/sys/class/net/%s/wireless" % ifc):
        info["tipo_enlace"] = "WIFI"
    elif ifc:
        info["tipo_enlace"] = "cable"
        try:
            with open("/sys/class/net/%s/speed" % ifc) as f:
                info["velocidad_mbps"] = int(f.read().strip())
        except (OSError, ValueError):
            pass
    return info

def versiones():
    v = {}
    for nombre, cmd in (("ping", ["ping", "-V"]), ("traceroute", ["traceroute", "--version"]),
                        ("dig", ["dig", "-v"]), ("iperf3", ["iperf3", "--version"])):
        if shutil.which(cmd):
            _, out = run_cmd(cmd, 5)
            v[nombre] = (out.strip().splitlines() or ["?"])
        else:
            v[nombre] = "FALTA"
    return v

def escribir_resumen(rows, outdir):
    grupos = {}
    for r in rows:
        clave = (r["dominio"], r["destino"], r["herramienta"], r["metrica"], r["unidad"])
        g = grupos.setdefault(clave, {"vals": [], "n_total": 0})
        g["n_total"] += 1
        if isinstance(r["valor"], (int, float)):
            g["vals"].append(r["valor"])
    path = os.path.join(outdir, "resumen.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["dominio", "destino", "herramienta", "metrica", "unidad",
                    "n_validas", "n_total", "min", "mediana", "max"])
        for (dom, dest, herr, met, uni), g in sorted(grupos.items()):
            v = g["vals"]
            w.writerow([dom, dest, herr, met, uni, len(v), g["n_total"],
                        round(min(v), 3) if v else "NA",
                        round(statistics.median(v), 3) if v else "NA",
                        round(max(v), 3) if v else "NA"])
    return path

def verificar(rows, ciclos_hechos):
    estados = {}
    for r in rows:
        estados[r["estado"]] = estados.get(r["estado"], 0) + 1
    sin_ts = sum(1 for r in rows if not r["ts_utc"])
    vacios = sum(1 for r in rows if r["valor"] in ("", None))
    return {"filas": len(rows), "ciclos_completados": ciclos_hechos,
            "filas_sin_timestamp": sin_ts, "filas_con_valor_vacio": vacios,
            "filas_por_estado": estados}

def chequeo_previo(cfg):
    """--check: herramientas, red de la sonda y alcance de los puertos iperf3."""
    print("== Herramientas ==")
    faltan = 0
    for t in ("ping", "traceroute", "dig", "iperf3"):
        ruta = shutil.which(t)
        print("  %-11s %s" % (t, ruta or "FALTA"))
        faltan += 0 if ruta else 1
    e = info_equipo()
    print("== Equipo y red ==")
    for k, v in e.items():
        print("  %-15s %s" % (k, v))
    if e["tipo_enlace"] == "WIFI":
        print("  AVISO: la interfaz es Wi-Fi; la actividad exige cable RJ45.")
    print("== Puertos iperf3 (conexion TCP) ==")
    for d in cfg["iperf"]["destinos"]:
        ok = puerto_tcp_abierto(d["host"], d["port"], cfg["iperf"]["precheck_timeout_s"])
        print("  %-18s %s:%d  %s" % (d["nombre"], d["host"], d["port"],
                                     "ABIERTO" if ok else "SIN RESPUESTA"))
    return 1 if faltan else 0

# =============================================================================
# 7. PROGRAMA PRINCIPAL
# =============================================================================
def main():
    ap = argparse.ArgumentParser(description="Medicion activa no invasiva (sin captura)")
    ap.add_argument("--config", help="JSON con valores a sobrescribir")
    ap.add_argument("--outdir", help="carpeta de salida")
    ap.add_argument("--cycles", type=int, help="numero de ciclos (por defecto 5)")
    ap.add_argument("--period-min", type=float, help="minutos entre inicios de ciclo (15)")
    ap.add_argument("--no-iperf", action="store_true", help="omitir iperf3")
    ap.add_argument("--traceroute-icmp", choices=["auto", "si", "no"],
                    help="auto = ICMP solo si se ejecuta como root")
    ap.add_argument("--probe-id", help="identificador de la sonda")
    ap.add_argument("--prueba", action="store_true",
                    help="modo ensayo corto (2 ciclos, 30 s, ping x3, iperf3 3 s)")
    ap.add_argument("--check", action="store_true", help="verificar herramientas y puertos y salir")
    args = ap.parse_args()

    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if args.config:
        with open(args.config, encoding="utf-8") as f:
            deep_update(cfg, json.load(f))
    if args.prueba:
        cfg.update({"ciclos": 2, "periodo_s": 30})
        cfg["ping"]["count"] = 3
        cfg["iperf"]["duracion_s"] = 3
    if args.cycles:
        cfg["ciclos"] = args.cycles
    if args.period_min:
        cfg["periodo_s"] = int(args.period_min * 60)
    if args.traceroute_icmp:
        cfg["traceroute"]["icmp"] = args.traceroute_icmp
    if args.probe_id:
        cfg["probe_id"] = args.probe_id
    if args.check:
        sys.exit(chequeo_previo(cfg))

    inicio = datetime.now(timezone.utc)
    run_id = "RUN-" + inicio.strftime("%Y%m%dT%H%M%SZ")
    outdir = args.outdir or "%s_%s" % (cfg["output_dir"], inicio.strftime("%Y%m%d_%H%M%S"))
    os.makedirs(outdir, exist_ok=True)
    sys.stdout = Tee(os.path.join(outdir, "sesion.log"))

    equipo, vers = info_equipo(), versiones()
    cfg_hash = hashlib.sha256(json.dumps(cfg, sort_keys=True).encode()).hexdigest()
    usar_iperf = not args.no_iperf

    print("== %s | %s ==" % (cfg["probe_id"], run_id))
    print("hostname=%s usuario=%s fecha=%s" % (equipo["hostname"], equipo["usuario"], local_iso()))
    print("interfaz=%s (%s) ip=%s gateway=%s" % (equipo["interfaz"], equipo["tipo_enlace"],
                                                 equipo["ip_sonda"], equipo["gateway"]))
    if equipo["tipo_enlace"] == "WIFI":
        print("AVISO: interfaz Wi-Fi. La actividad exige conexion por cable RJ45.")
    for h, v in vers.items():
        if v == "FALTA" and (h != "iperf3" or usar_iperf):
            print("AVISO: falta la herramienta %s (sus filas saldran como NO_ENCONTRADA)." % h)
    print("Captura de paquetes: DESACTIVADA (solo trafico propio de la sonda)")
    print("Ciclos=%d periodo=%ds -> duracion minima aprox. %.0f min" % (
        cfg["ciclos"], cfg["periodo_s"], (cfg["ciclos"] - 1) * cfg["periodo_s"] / 60))

    run_info = {"run_id": run_id, "probe_id": cfg["probe_id"],
                "inicio_utc": inicio.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                "inicio_local": local_iso(), "fin_utc": None, "duracion_s": None,
                "equipo": equipo, "herramientas": vers, "captura_paquetes": False,
                "config_sha256": cfg_hash, "config": cfg}
    run_path = os.path.join(outdir, "run.json")

    def guardar_run():
        with open(run_path, "w", encoding="utf-8") as f:
            json.dump(run_info, f, indent=2, ensure_ascii=False)

    guardar_run()
    reg = Registro(outdir)
    t0, hechos = time.monotonic(), 0
    try:
        for n in range(1, cfg["ciclos"] + 1):
            objetivo = t0 + (n - 1) * cfg["periodo_s"]
            espera = objetivo - time.monotonic()
            if espera > 0:
                print("\n(esperando %.0f s para el ciclo %d; Ctrl+C para terminar)" % (espera, n))
                time.sleep(espera)
            elif n > 1:
                print("AVISO: el ciclo anterior excedio el periodo; se inicia sin espera.")
            ejecutar_ciclo(n, cfg["ciclos"], cfg, reg, usar_iperf)
            hechos += 1
    except KeyboardInterrupt:
        print("\nInterrumpido por el usuario.")
    finally:
        fin = datetime.now(timezone.utc)
        reg.cerrar()
        resumen = escribir_resumen(reg.rows, outdir)
        run_info["fin_utc"] = fin.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        run_info["fin_local"] = local_iso()
        run_info["duracion_s"] = round((fin - inicio).total_seconds(), 1)
        run_info["verificacion"] = verificar(reg.rows, hechos)
        guardar_run()
        print("\n== Fin de la sesion ==")
        print("inicio: %s\nfin   : %s\nduracion: %.1f min | ciclos completos: %d/%d" % (
            run_info["inicio_utc"], run_info["fin_utc"], run_info["duracion_s"] / 60,
            hechos, cfg["ciclos"]))
        if run_info["duracion_s"] < 3600 and not args.prueba:
            print("AVISO: la sesion duro menos de 1 hora; no cumple el minimo de la actividad.")
        print("verificacion:", json.dumps(run_info["verificacion"], ensure_ascii=False))
        print("archivos en %s: run.json, mediciones.csv, mediciones.json, resumen.csv, sesion.log"
              % outdir)
        print("resumen:", resumen)

if __name__ == "__main__":
    main()