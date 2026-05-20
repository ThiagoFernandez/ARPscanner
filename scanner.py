import socket
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import colorama
import requests
from scapy.all import ARP, Ether, srp

import auxiliar

socket.gethostbyname(socket.gethostname())
colorama.init()


def get_mi_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # no manda nada, solo determina la interfaz
        return s.getsockname()[0]
    finally:
        s.close()


def get_paquete():
    resultado = auxiliar.validat_args()
    if resultado == -1:
        return -1

    arp = ARP(
        pdst=resultado
    )  # yo le paso la subred y scapy la expande a todo su dominio
    ether = Ether(
        dst="ff:ff:ff:ff:ff:ff"
    )  # Es la MAC de broadcast, con esto todos los dipositivos reciben el broadcast

    paquete = ether / arp
    return paquete


def enviar_paquete(paquete):
    return srp(
        paquete, timeout=2, verbose=0
    )  # el 2 es a eleccion y el 0 es porque no necesito lo q me devuelve eso


def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = "N/A"
    return hostname


def get_vendor(mac):
    try:
        oui = mac[:8]  # los primeros 3 pares
        response = requests.get(f"https://api.macvendors.com/{oui}", timeout=3)
        return response.text if response.status_code == 200 else "N/A"
    except requests.RequestException:
        return "N/A"


def get_resultados(si_rta):
    dispositivos = []
    for enviado, recibido in si_rta:
        dispositivos.append(
            {
                "ip": recibido[ARP].psrc,
                "mac": recibido[Ether].src,
                "hostname": None,
                "vendor": None,
            }
        )

    # hostnames en paralelo
    ips = [d["ip"] for d in dispositivos]
    with ThreadPoolExecutor(max_workers=10) as executor:
        hostnames = list(executor.map(get_hostname, ips))
    for d, hostname in zip(dispositivos, hostnames):
        d["hostname"] = hostname

    # vendors secuencial con delay porque sino me como el limit rate
    for d in dispositivos:
        d["vendor"] = get_vendor(d["mac"])
        time.sleep(1)

    dispositivos.sort(key=lambda d: tuple(int(oct) for oct in d["ip"].split(".")))
    return dispositivos


def ver_resultados(resultados, si, no):
    # ancho max x col
    anchos = {
        "ip": max(len(d["ip"]) for d in resultados),
        "mac": max(len(d["mac"]) for d in resultados),
        "hostname": max(len(d["hostname"]) for d in resultados),
        "vendor": max(len(d["vendor"]) for d in resultados),
    }

    # que no sean menores que el header porque sino es cualquier cosa
    anchos["ip"] = max(anchos["ip"], len("IP"))
    anchos["mac"] = max(anchos["mac"], len("MAC"))
    anchos["hostname"] = max(anchos["hostname"], len("Hostname"))
    anchos["vendor"] = max(anchos["vendor"], len("Vendor"))

    # header
    print(
        f"{'#':<4} {'IP':<{anchos['ip']}} {'MAC':<{anchos['mac']}} {'Hostname':<{anchos['hostname']}} {'Vendor':<{anchos['vendor']}}"
    )
    print(
        "-"
        * (4 + anchos["ip"] + anchos["mac"] + anchos["hostname"] + anchos["vendor"] + 4)
    )

    # filas
    mi_ip = get_mi_ip()
    for idx, d in enumerate(resultados, 1):
        if mi_ip == d["ip"]:
            print(
                f"{colorama.Fore.GREEN}{idx:<4} {d['ip']:<{anchos['ip']}} {d['mac']:<{anchos['mac']}} {d['hostname']:<{anchos['hostname']}} {d['vendor']:<{anchos['vendor']}}{colorama.Style.RESET_ALL}"
            )
        else:
            print(
                f"{idx:<4} {d['ip']:<{anchos['ip']}} {d['mac']:<{anchos['mac']}} {d['hostname']:<{anchos['hostname']}} {d['vendor']:<{anchos['vendor']}}"
            )

    print(f"\nTotal con respuesta: {len(si)}\nTotal sin respuesta: {len(no)}")


def start_scanner():
    start = datetime.now()
    paquete = get_paquete()
    si_rta, no_rta = enviar_paquete(paquete)
    dispositivos = get_resultados(si_rta)
    ver_resultados(dispositivos, si_rta, no_rta)
    end = datetime.now()
    elapsed = (end - start).total_seconds()
    print(f"Tiempo: {elapsed:.2f} segundos")
    auxiliar.save_file(dispositivos)
    print("Resultados guardados")
