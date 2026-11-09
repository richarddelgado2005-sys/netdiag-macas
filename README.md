# NetDiag-Macas: Script de Medición Activa de Red 

**Asignatura:** Proyecto Integrador

**Nombre:** Richard Alexander Delgado Guaraca  

**Institución:** Escuela Superior Politécnica de Chimborazo (ESPOCH) - Sede Riobamba  

**Laboratorio:** Redes y Telecomunicaciones  

**Entregables:** E1 (Script y README en Git) | E2 (Dataset) | E3 (Registro Breve PDF) | E4 (Evidencia de Logs)

## 📋 1. Descripción del Proyecto

Este repositorio contiene la **sonda de medición activa no invasiva** (`sonda_medicion.py`) desarrollada para el diagnóstico de la infraestructura de red LAN/WAN desde la Sede Riobamba. El script ejecuta pruebas periódicas automatizadas utilizando herramientas estándar de red (`ping`, `traceroute`, `dig`, `iperf3`) sin realizar captura de paquetes ni inspección de tráfico de terceros (desactivada la función `dumpcap`/SPAN conforme a las políticas de privacidad y restricciones de la Fase 1).

## 🛠️ 2. Prerrequisitos y Dependencias

- **Sistema Operativo:** Linux (Arch Linux)
- **Intérprete:** Python 3.8 o superior (utiliza exclusivamente la biblioteca estándar)
- **Herramientas del sistema:**
  - `ping` (iputils)
  - `traceroute`
  - `dig` (bind)
  - `iperf3` (cliente)

### Instalación de dependencias en Arch Linux

```bash
sudo pacman -Syu python traceroute bind iperf3 iputils
```

## 🚀 3. Modo de Uso y Ejecución

### A. Verificación previa de herramientas y red (`--check`)

Antes de iniciar la prueba de 1 hora, ejecute el chequeo previo para confirmar que la interfaz sea por cable RJ45 y que las herramientas estén disponibles:

```bash
python3 sonda_medicion.py --check
```

### B. Ejecución completa del laboratorio (1 hora continua - 5 ciclos)

Para cumplir con los requisitos obligatorios de la actividad (5 ciclos cada 15 minutos = 60 minutos):

```bash
sudo ./sonda_medicion.py --cycles 5 --period-min 15 --outdir salida_lab_20261109_134242
```

*Nota: Se recomienda `sudo` para permitir que `traceroute` utilice sondas ICMP (`-I`) y determinar con precisión la topología de saltos.*

### C. Modo de ensayo rápido (`--prueba`)

Para verificar el correcto funcionamiento en 2 ciclos de 30 segundos:

```bash
python3 sonda_medicion.py --prueba
```

## 📂 4. Estructura de la Carpeta de Salida

Cada ejecución genera una carpeta con el sufijo de fecha/hora conteniendo 5 archivos esenciales:

```text
salida_lab_20261109_134242/
├── run.json         # Metadatos de la sesión (hostname, IP, interfaz, hashes, tiempos UTC/local)
├── mediciones.csv   # Dataset primario en formato largo (una fila por métrica)
├── mediciones.json  # Dataset primario en formato JSON estructurado
├── resumen.csv      # Matriz estadística (mínimo, mediana, máximo por destino y métrica)
└── sesion.log       # Registro completo de consola impreso durante la sesión
```

## 📊 5. Parámetros y Destinos de Medición

- **Destinos Institucionales (Riobamba/ESPOCH):**
  - `srv_referencia` (`172.17.103.102`): Servidor de referencia iperf3 / ping / traceroute.
  - `dns1_espoch` (`172.17.102.39`) y `dns2_espoch` (`172.17.102.40`): Servidores DNS institucionales.

- **Destinos Externos Autorizados:**
  - `google_dns` (`8.8.8.8`): Servidor DNS público de Google.
  - `cloudflare` (`1.1.1.1`): Servidor DNS público de Cloudflare.
  - `speedtest_masnet` (`speedtest.masnet.ec:5201`): Servidor externo de pruebas iperf3 TCP.

## 🔒 6. Política de Privacidad y Ética de Red

La sonda genera **únicamente su propio tráfico experimental** y no intercepta, modifica ni examina paquetes pertenecientes a usuarios o sistemas de terceros en la red de la ESPOCH.

## 🤝 7. Historial de Commits y Registro de Git

Para clonar y subir la evidencia al repositorio oficial del equipo:

```bash
git add sonda_medicion.py README.md salida_lab_20261109_134242/
git commit -m "feat(netdiag): entrega completa de validacion de laboratorio E1-E4"
git push origin main
```
