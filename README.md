# 🔐 Secure Multi-Zone Network Infrastructure on OPNsense

A complete reference implementation for designing a **modern network infrastructure** using open-source components:
- **OPNsense Firewall**
- **HAProxy Reverse Proxy**
- **Unbound DNS Resolver**
- **Active Directory DNS**
- **OpenVPN (Split-Tunnel)**
- **Let’s Encrypt SSL Management**

This configuration provides:
- Centralized SSL termination and certificate management  
- Isolated zones (LAN, DMZ, VPN, WAN)  
- Secure remote access (split-tunnel VPN)  
- Internal DNS with split-horizon resolution  
- Explicit firewall segmentation and access control  

---

## 🧩 Infrastructure Overview

| Zone | Example Subnet | Purpose |
|------|----------------|----------|
| **WAN** | Public IP | Internet access & SSL termination |
| **DMZ** | 10.0.20.0/24 | Public-facing servers (mail, web, DNS) |
| **LAN** | 10.0.10.0/24 | Internal systems, AD, file servers |
| **VPN (OpenVPN)** | 10.0.30.0/24 | Secure remote access users |

---

## ⚙️ Core Components

| Component | Description |
|------------|-------------|
| **OPNsense** | Acts as core firewall, router, and service host |
| **Unbound DNS** | Internal recursive resolver with forwarding |
| **HAProxy Plugin** | Handles SSL termination and reverse proxy routing |
| **Let’s Encrypt Plugin** | Automatically manages SSL certificates |
| **Windows AD DNS (optional)** | Hosts internal domain zones |
| **OpenVPN** | Provides split-tunnel encrypted remote access |

---

## 🧱 Network Diagram (Mermaid)

```mermaid
flowchart TD
A[Internet] -->|443/1194| B[OPNsense Firewall]
B -->|LAN 10.0.10.0/24| C[Internal Network (AD, File, Apps)]
B -->|DMZ 10.0.20.0/24| D[Public Servers (Web, Mail)]
B -->|VPN 10.0.30.0/24| E[Remote Users (OpenVPN)]
B -->|WAN| F[Internet/Cloud]
D -->|DNS| G[Unbound Resolver]
🔒 SSL & Reverse Proxy (HAProxy)
Frontend Configuration
Setting	Example
Interface	WAN + DMZ
Port	443
Certificate	Let's Encrypt (Wildcard or specific host)
Type	HTTPS (SSL Offloading)
Backend	Internal server (e.g. mail/web on DMZ)
Backend Configuration
Setting	Example
Server	10.0.20.5
Port	443
SSL Check	Enabled
Health Check	HTTP(S) GET /status

Result:
All HTTPS requests terminate at OPNsense → decrypted → forwarded internally to backend servers.
One SSL certificate, consistent for both internal and public access.

🌐 DNS Configuration (Split-Horizon)
OPNsense – Unbound DNS
Setting	Value
Network Interfaces	LAN, DMZ, VPN
Outgoing Interfaces	WAN
Forwarding Mode	✅ Enabled
Upstream DNS	1.1.1.1, 8.8.8.8
Domain Overrides	corp.local → internal DNS server (AD)
Active Directory DNS (optional)
Setting	Value
Forwarders	OPNsense IP (LAN or DMZ)
Internal Records	Internal service IPs (e.g., mail.corp.local → 10.0.20.1)

Behavior:

Internal clients resolve internal zones internally.

External lookups are forwarded through OPNsense → WAN.

Split-horizon ensures the same hostname works inside and outside securely.

🧾 OpenVPN Server Configuration (Split-Tunnel)
Field	Value
Role	Server
Protocol	UDP
Port	1194
Device Type	tun
Server Network	10.0.30.0/24
Local Networks	10.0.10.0/24, 10.0.20.0/24
Redirect Gateway	❌ Disabled (Split-Tunnel)
Certificate	VPN-Server
Verify Client Certificate	Required
TLS Key	tls-crypt
Cipher	AES-256-GCM
Auth Digest	SHA256
TLS Min Version	1.2

Advanced Push Options

push "route 10.0.10.0 255.255.255.0"
push "route 10.0.20.0 255.255.255.0"
push "dhcp-option DOMAIN corp.local"
push "dhcp-option DNS 10.0.10.1"


Result:
Only LAN and DMZ traffic goes through VPN; Internet stays local.
This is efficient and ideal for hybrid work.

🔑 Authentication and MFA
Setting	Description
Backend	Local User Database
MFA	Optional TOTP integration (System → Access → Servers → TOTP)
Strict CN Matching	Enforce user ↔ certificate name match
Renegotiate Time	3600 sec
Auth Token Lifetime	86400 sec (optional for persistent sessions)
🧳 Client Export & Deployment

Path: VPN → OpenVPN → Client Export

Field	Example
Server	OpenVPN-Server (UDP 1194)
Hostname	vpn.exampledomain.com
Port	1194
Use Random Local Port	✅
Validate Server Subject	✅
Disable Password Save	✅
OTP Challenge	Optional (if MFA enabled)

Custom Config Example

route 10.0.10.0 255.255.255.0
route 10.0.20.0 255.255.255.0
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
auth SHA256
keepalive 10 60
explicit-exit-notify 1


Each user receives a personal .ovpn profile with their own embedded certificate.

🧱 Firewall Policy Matrix
Source Zone	Destination	Ports	Action	Purpose
WAN	OPNsense	443	Allow	HTTPS to HAProxy
WAN	OPNsense	1194	Allow	OpenVPN access
LAN	Any	Any	Allow (with policy control)	Internal access
DMZ	WAN	80, 443	Allow	Outbound web
DMZ	LAN	Any	Deny	Isolate internal network
VPN	LAN/DMZ	53, 443, 445	Allow	DNS, HTTPS, SMB (if required)
DMZ → Mail Server	443	Deny	Prevent direct access, enforce HAProxy proxy-only	
🧪 Verification
🧭 From a VPN client:
# Check routes (split-tunnel)
route print
# Test internal access
ping 10.0.10.10
# Test DNS
nslookup internal.corp.local
# Test Internet stays local
tracert 8.8.8.8


Expected:

Only internal routes appear under VPN

Internal services reachable

Internet traffic bypasses VPN

🧠 Key Security Practices

Terminate all SSL/TLS at OPNsense (HAProxy)

Isolate DMZ and LAN with explicit rules

Use TLS ≥ 1.2 and modern ciphers

Disable compression in VPN (CRIME protection)

Enable OCSP/CRL for certificate validation

Auto-renew SSL via Let’s Encrypt (DNS-01 challenge preferred)

Use per-user VPN certificates

Regularly review logs (VPN, HAProxy, Unbound)
