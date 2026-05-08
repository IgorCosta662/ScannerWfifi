# 🔐 WifiScanner – Ferramenta de Auditoria de Protocolo Wireless WPS

**Waircut** é uma ferramenta de código aberto escrita em Python para auditoria de segurança de redes Wi-Fi, com foco na exploração de vulnerabilidades do protocolo **WPS (Wi‑Fi Protected Setup)** e análise de tráfego de rede.

> ⚠️ **Aviso legal:** Esta ferramenta foi desenvolvida para fins educacionais e de testes de penetração em redes próprias ou autorizadas. O uso indevido pode violar leis locais. O autor não se responsabiliza pelo mau uso.

![Python](https://img.shields.io/badge/python-3.6+-blue)
![Licença](https://img.shields.io/badge/license-MIT-green)
![Plataforma](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)

---

## 📋 Funcionalidades

- **📡 Escaneamento de redes Wi‑Fi**  
  Detecção de APs com WPS ativo, exibindo BSSID, SSID, fabricante, canal e intensidade do sinal.

- **🔍 Identificação automática de fabricantes**  
  Base de dados de OUI expandida com mais de 100 fabricantes, incluindo ISPs brasileiros (Sercomm, Fiberhome, Sagemcom, etc.).

- **📊 Análise de segurança da rede**  
  Avaliação de força da autenticação, criptografia, canal, presença de WPS e score geral (0‑100).

- **🗝️ Brute‑force de PIN WPS**  
  Teste de PINs padrão específicos do fabricante, seguidos de uma wordlist comum.

- **⚡ Ataque Pixie Dust** *(indicado como não implementado na versão atual)*

- **📚 Ataque de dicionário WPA/WPA2 (simulado no Windows)**  
  Testa senhas comuns contra um handshake capturado (requer modo monitor para ataque real).

- **📡 Ataque de desautenticação**  
  Força a desconexão de clientes para captura de handshake.

- **👥 Escaneamento de clientes conectados**  
  Lista os dispositivos associados a um AP específico.

- **🌐 Analisador de tráfego estilo Wireshark**  
  Captura e exibe estatísticas de protocolos, IPs, consultas DNS, requisições HTTP e credenciais em texto claro.

- **🔍 Visualizador de pacotes em tempo real**  
  Filtragem por protocolo (HTTP, DNS, TCP, UDP, etc.).

- **🖥️ Descoberta de dispositivos na rede**  
  ARP scan, ping sweep e NetBIOS (Windows) para mapear todos os hosts.

- **🔒 Teste de força de senha**  
  Avalia complexidade, padrões comuns e estima tempo para quebra.

- **📋 Credenciais padrão de roteadores**  
  Base de dados com mais de 15 fabricantes, incluindo URLs de administração, usuário/senha padrão e vulnerabilidades conhecidas.

---

## 🖥️ Modo de operação

O Waircut funciona tanto em **Linux** quanto em **Windows**, com algumas limitações:

| Funcionalidade               | Linux (modo monitor) | Windows           |
|------------------------------|----------------------|-------------------|
| Escaneamento de APs          | ✅ Scapy + sniff     | ✅ netsh / wlanapi|
| Detecção WPS                 | ✅ Análise de beacons| ⚠️ Baseado em heurísticas |
| Brute‑force WPS              | ✅                   | ⚠️ Simulação     |
| Ataque de desautenticação    | ✅                   | ❌                |
| Captura de tráfego raw       | ✅                   | ❌                |
| Analisador de tráfego        | ✅                   | ✅ (tráfego local)|
| Descoberta de dispositivos   | ✅                   | ✅                |
| Força de senha / credenciais | ✅                   | ✅                |

---

## 📦 Requisitos

- **Python 3.6+**
- **Scapy** – `pip install scapy`
- **Privilégios de administrador/root**  
  Linux: executar com `sudo`  
  Windows: executar o terminal como **Administrador**

No **Windows**, para melhor funcionamento, recomenda‑se instalar o **Npcap** com suporte a *“Raw 802.11 Traffic”*.

---

## 🚀 Instalação

```bash
# Clone o repositório
git clone https://github.com/kalyel473/wifi.git
cd WifiScanner
