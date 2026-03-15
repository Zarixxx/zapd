<div align="center">

```
███████╗ █████╗ ██████╗ ██████╗
╚══███╔╝██╔══██╗██╔══██╗██╔══██╗
  ███╔╝ ███████║██████╔╝██║  ██║
 ███╔╝  ██╔══██║██╔═══╝ ██║  ██║
███████╗██║  ██║██║     ██████╔╝
╚══════╝╚═╝  ╚═╝╚═╝     ╚═════╝
```

**Network & Threat Analysis Tool**

![C](https://img.shields.io/badge/Language-C-red?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-red?style=flat-square)
![Author](https://img.shields.io/badge/Author-Zarixxx-black?style=flat-square)

</div>

---

ZapD es una herramienta de línea de comandos escrita en C para análisis de redes y amenazas. Binario nativo, sin dependencias externas en tiempo de ejecución, sin Python, sin intérpretes. Solo compilas una vez y tienes un ejecutable que puedes usar como cualquier herramienta del sistema.

---

## Instalación

### Requisitos

- `gcc` — compilador C (viene en CachyOS/Arch por defecto)
- `openssl` — solo para el módulo VirusTotal

```bash
sudo pacman -S openssl          # para el módulo vt
sudo pacman -S traceroute       # para zapd ping --trace
sudo pacman -S bind-tools       # para zapd whois --dns (dig)
```

### Compilar e instalar

```bash
git clone https://github.com/Zarixxx/zapd.git
cd zapd
make
sudo make install
```

Esto instala el binario en `/usr/local/bin/zapd` y puedes usarlo desde cualquier terminal.

### Desinstalar

```bash
sudo make uninstall
```

---

## Comandos

### `zapd scan` — Escáner de puertos

Realiza conexiones TCP o UDP reales a cada puerto del objetivo para determinar cuáles están abiertos, cerrados o filtrados por un firewall.

- **Abierto** — el puerto acepta conexiones, hay un servicio escuchando.
- **Cerrado** — el host responde rechazando la conexión (RST). No hay servicio.
- **Filtrado** — no hay respuesta. Un firewall está descartando los paquetes silenciosamente.

```bash
zapd scan <target> [opciones]
```

| Opción | Descripción | Default |
|--------|-------------|---------|
| `-p <puertos>` | Rango de puertos a escanear. Formatos: `1-1024`, `22,80,443`, `1-65535` | `1-1024` |
| `-T <1-5>` | Preset de velocidad (ver tabla abajo) | `3` |
| `-t <n>` | Sobreescribe el número de hilos del preset | — |
| `--timeout <s>` | Sobreescribe el timeout del preset en segundos (acepta decimales) | — |
| `-u` | Modo UDP en vez de TCP | off |
| `-r` | Aleatoriza el orden de los puertos antes de escanear | off |
| `-b` | Banner grabbing: intenta leer qué software corre en cada puerto | off |
| `-O` | OS fingerprinting: adivina el sistema operativo por el TTL | off |
| `--show-closed` | Muestra también los puertos cerrados y filtrados | off |
| `-o <fichero>` | Guarda los resultados en un fichero JSON | — |

#### Presets de timing (`-T`)

| Nivel | Nombre | Hilos | Timeout | Cuándo usarlo |
|-------|--------|-------|---------|---------------|
| `-T1` | Paranoid | 1 | 5.0s | Escaneo muy lento, mínimo ruido en la red |
| `-T2` | Sneaky | 10 | 3.0s | Lento, poco ruido |
| `-T3` | Normal | 100 | 1.5s | Equilibrio velocidad/fiabilidad (por defecto) |
| `-T4` | Aggressive | 300 | 0.8s | Rápido, puede perder puertos lentos |
| `-T5` | Insane | 500 | 0.3s | Muy rápido, puede dar falsos negativos |

#### Ejemplos

```bash
# Escaneo básico de los 1024 puertos más comunes
zapd scan 192.168.1.1

# Escaneo completo de todos los puertos
zapd scan 192.168.1.1 -p 1-65535 -T4

# Puertos específicos con detección de banners y OS
zapd scan 192.168.1.1 -p 22,80,443,3306,5432 -b -O

# Escaneo UDP (DNS, SNMP, DHCP, NTP...)
zapd scan 192.168.1.1 -u -p 53,67,68,123,161

# Ver también puertos filtrados (firewall)
zapd scan 192.168.1.1 -p 1-1024 --show-closed

# Orden aleatorio de puertos
zapd scan 192.168.1.1 -r -T3

# Guardar resultado en JSON
zapd scan 192.168.1.1 -p 1-1024 -b -o resultado.json

# Todo junto
zapd scan 192.168.1.1 -p 1-65535 -T4 -r -b -O --show-closed -o full.json
```

---

### `zapd vt` — Análisis VirusTotal

Consulta la API real de VirusTotal v3 para analizar URLs, IPs, dominios o hashes de archivos contra más de 70 motores antivirus simultáneamente.

Requiere una API key gratuita: [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us)

```bash
zapd vt <target> [opciones]
```

| Opción | Descripción | Default |
|--------|-------------|---------|
| `-t <tipo>` | Tipo de análisis: `url`, `ip`, `domain`, `hash` | `url` |
| `-k <clave>` | API key de VirusTotal | variable `VT_API_KEY` |
| `-o <fichero>` | Guarda el informe JSON completo en un fichero | — |

#### Configurar la API key (una sola vez)

```bash
echo 'export VT_API_KEY=tu_clave_aqui' >> ~/.zshrc
source ~/.zshrc
```

A partir de ahí no hace falta pasar `-k` nunca más.

#### Qué muestra

- **Veredicto** — CLEAN, SUSPICIOUS o MALICIOUS
- **Estadísticas** — cuántos motores lo detectan como malicioso, sospechoso o limpio
- **Reputación** — puntuación de reputación de la IP/dominio en VT
- **País y ASN** — para IPs, el país y el propietario del bloque de IPs
- **Metadatos del fichero** — para hashes: nombre, tipo, MD5, SHA256
- **Tabla de detecciones** — qué motores lo detectan y con qué nombre

#### Ejemplos

```bash
# Analizar una URL sospechosa
zapd vt https://sitio-sospechoso.com

# Analizar la reputación de una IP
zapd vt 8.8.8.8 -t ip

# Analizar un dominio
zapd vt malware.ejemplo.com -t domain

# Analizar un fichero por su hash MD5 o SHA256
zapd vt d41d8cd98f00b204e9800998ecf8427e -t hash
zapd vt e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 -t hash

# Pasar la API key directamente (sin variable de entorno)
zapd vt https://sitio.com -k TU_API_KEY

# Guardar informe completo
zapd vt https://sitio.com -o informe.json
```

---

### `zapd ping` — Ping y Traceroute

Envía paquetes ICMP al objetivo y muestra la latencia de cada respuesta. Con `--trace` realiza un traceroute mostrando todos los saltos (routers) entre tu máquina y el destino.

```bash
zapd ping <target> [opciones]
```

| Opción | Descripción | Default |
|--------|-------------|---------|
| `-c <n>` | Número de paquetes ICMP a enviar | `4` |
| `--trace` | Ejecuta traceroute tras el ping | off |
| `--max-hops <n>` | Número máximo de saltos para el traceroute | `30` |

> **Nota:** el traceroute requiere `traceroute` instalado: `sudo pacman -S traceroute`

#### Ejemplos

```bash
# Ping básico
zapd ping 8.8.8.8

# Más paquetes para mejor estadística
zapd ping google.com -c 20

# Ping + traceroute
zapd ping 8.8.8.8 --trace

# Traceroute con límite de saltos
zapd ping google.com --trace --max-hops 15
```

---

### `zapd whois` — WHOIS y DNS

Se conecta directamente a los servidores WHOIS por TCP (puerto 43) para obtener información sobre quién registró un dominio, cuándo expira, sus servidores de nombres, etc. Con `--dns` consulta también todos los registros DNS del dominio.

```bash
zapd whois <target> [opciones]
```

| Opción | Descripción |
|--------|-------------|
| `--dns` | Consulta registros DNS: A, AAAA, MX, NS, TXT, CNAME, SOA |
| `-o <fichero>` | Guarda los resultados en JSON |

> **Nota:** `--dns` requiere `dig`: `sudo pacman -S bind-tools`

#### Qué muestra

- **WHOIS** — registrador, fechas de creación/expiración/actualización, estado, servidores de nombres, organización, país
- **DNS** — todos los registros del dominio cuando se usa `--dns`

#### Ejemplos

```bash
# WHOIS básico
zapd whois google.com

# WHOIS + todos los registros DNS
zapd whois mozilla.org --dns

# Consulta de una IP
zapd whois 8.8.8.8

# Guardar resultado
zapd whois ejemplo.com --dns -o whois.json
```

---

## Ayuda rápida

```bash
zapd --help           # ayuda general
zapd scan --help      # ayuda detallada del escáner
zapd vt --help        # ayuda del módulo VirusTotal
zapd ping --help      # ayuda del ping/traceroute
zapd whois --help     # ayuda del WHOIS/DNS
zapd --version        # versión actual
```

---

## Aviso legal

Usa ZapD únicamente en sistemas y redes para los que tengas autorización explícita. El escaneo de puertos no autorizado puede ser ilegal en tu jurisdicción. El autor no se hace responsable del mal uso de esta herramienta.

---

<div align="center">
Hecho con ❤️ por <a href="https://github.com/Zarixxx">Zarixxx</a>
</div>
