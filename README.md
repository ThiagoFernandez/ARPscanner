# ARPscanner

Escáner de descubrimiento de hosts para redes locales, construido en Python con **Scapy**. Mapea todos los dispositivos activos de una subred vía ARP, los identifica por fabricante y hostname, y permite comparar dos escaneos para detectar qué cambió en la red.

Proyecto de la Fase 2 del roadmap de Python para ciberseguridad — enfocado en la capa 2, ARP y monitoreo de inventario de red.

---

## Features

- **Descubrimiento ARP por broadcast** — encuentra dispositivos aunque no respondan ping o tengan el firewall cerrado
- **Identificación de fabricante** — lookup del OUI de cada MAC contra la API de macvendors
- **Resolución de hostname** — DNS inverso en paralelo con `ThreadPoolExecutor`
- **Tabla autoajustable** — el ancho de cada columna se calcula según el contenido; tu propia máquina aparece resaltada en verde
- **Exportación a JSON** con timestamp en el nombre del archivo
- **Comparación entre escaneos** — toma dos JSON y reporta dispositivos nuevos, desaparecidos y cambios de IP
- **Modo watch** — reescanea en bucle hasta Ctrl+C
- **Validación de red** — acepta solo rangos privados con máscara coherente

---

## Instalación

```bash
git clone https://github.com/ThiagoFernandez/ARPscanner.git
cd ARPscanner
pip install scapy colorama requests
```

En Windows hace falta [Npcap](https://npcap.com/) para enviar tramas ARP.

---

## Uso

```bash
# Linux/macOS: sockets crudos, requiere root
sudo python main.py 192.168.1.0/24

# Windows: terminal como administrador
python main.py 192.168.1.0/24
```

Al arrancar aparece el menú:

```
1. scan            → escaneo único, muestra la tabla y guarda el JSON
2. compare results → elige dos JSON previos y muestra las diferencias
3. watch           → escaneo en bucle cada 10 segundos
4. Exit
```

---

## Output

### Escaneo

```
#    IP            MAC                Hostname          Vendor
------------------------------------------------------------------
1    192.168.1.1   a4:5e:60:c1:22:9f  router.home       TP-Link
2    192.168.1.14  3c:22:fb:81:04:2a  N/A               Apple, Inc.
3    192.168.1.35  d8:3a:dd:6f:11:c0  DESKTOP-ZANTO     Intel Corporate
4    192.168.1.52  b8:27:eb:44:aa:1d  raspberrypi       Raspberry Pi Foundation

Total con respuesta: 4
Total sin respuesta: 250
Tiempo: 6.42 segundos
Resultados guardados
```

### Comparación

```
NUEVO: {'ip': '192.168.1.77', 'mac': '5c:cf:7f:19:aa:03', 'hostname': 'N/A', 'vendor': 'Espressif Inc.'}
DESAPARECIDO: {'ip': '192.168.1.14', 'mac': '3c:22:fb:81:04:2a', 'hostname': 'N/A', 'vendor': 'Apple, Inc.'}
IP cambiada: b8:27:eb:44:aa:1d era 192.168.1.52 --> ahora: 192.168.1.61
-Diferencia total-
Cantidad de dispositivos en el registro mas reciente: 5
Cantidad de dispositivos en el registro 'viejo': 4
```

---

## Cómo funciona

### Por qué ARP y no ping

Un barrido ICMP solo encuentra hosts que decidan responder: muchos sistemas descartan el ping por firewall. ARP no es opcional — si un dispositivo quiere comunicarse en la LAN, tiene que responder al `who-has`, porque es el mecanismo con el que se resuelven las MAC de la propia subred. Por eso un barrido ARP encuentra dispositivos que un barrido ICMP no ve.

El escaneo se arma como una trama Ethernet a la MAC de broadcast con una petición ARP adentro:

```python
Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.0/24")
```

Scapy expande el CIDR a todo el rango y `srp()` envía y recibe en capa 2 en una sola operación.

### Comparación por MAC, no por IP

El diff usa operaciones de conjuntos sobre las MAC, no sobre las IP. La IP de un dispositivo cambia con cada renovación DHCP; la MAC es estable. Así, un dispositivo que pasó de `.52` a `.61` se reporta como un cambio de IP y no como un dispositivo nuevo más uno desaparecido — que es el falso positivo típico de comparar por IP.

### Fabricante y rate limiting

El OUI son los tres primeros bytes de la MAC, asignados por el IEEE a cada fabricante. Se consultan contra `api.macvendors.com`, que es gratuita pero limita por tasa, así que las consultas van secuenciales con una pausa de 1 s entre cada una. Los hostnames, en cambio, se resuelven en paralelo con 10 hilos, porque el DNS inverso es local y no tiene ese límite.

---

## Dependencias

| Librería | Instalación | Uso |
|----------|-------------|-----|
| `scapy` | `pip install scapy` | Construcción y envío de tramas ARP |
| `requests` | `pip install requests` | Consulta a la API de fabricantes |
| `colorama` | `pip install colorama` | Colores cross-platform |
| `socket`, `json`, `os`, `time`, `datetime`, `concurrent.futures` | stdlib | Red, persistencia y paralelismo |

---

## Consideraciones legales

Escanear una red revela su inventario de dispositivos. Usar solo en redes propias o con autorización explícita del responsable.

---

## Limitaciones conocidas

- Solo IPv4 y solo la subred local — ARP no atraviesa routers por diseño
- Acepta únicamente rangos privados (`10.x`, `172.16-31.x`, `192.168.x`)
- El lookup de fabricante tarda ~1 s por dispositivo por el rate limit de la API
- Sin conexión a internet, la columna Vendor queda en `N/A`
- El intervalo del modo watch está fijo en 10 s, hardcodeado
- Requiere privilegios de administrador por los sockets crudos

---

*Parte del roadmap de Python para Ciberseguridad*
