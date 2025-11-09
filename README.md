# 🔐 Secure Multi-Zone Network Infrastructure on OPNsense

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OPNsense](https://img.shields.io/badge/OPNsense-22%2B-blue)](https://opnsense.org/)
[![Status: Production Ready](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)](/)
[![Last Updated](https://img.shields.io/badge/Last%20Updated-2025-blue)](/docs)

A complete, production-ready reference implementation for building a **modern, secure network infrastructure** using open-source components. This project provides enterprise-grade network segmentation, SSL termination, VPN access, and DNS resolution with centralized security controls.

## 📋 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Configuration Guide](#configuration-guide)
- [Security Best Practices](#security-best-practices)
- [Verification & Testing](#verification--testing)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 Overview

This repository contains detailed configurations and implementation guides for a comprehensive network infrastructure built on OPNsense. It's designed for organizations requiring secure network segmentation, centralized SSL management, split-tunnel VPN capabilities, and internal DNS resolution with Active Directory integration.

### Use Cases

- **Hybrid Work Infrastructure**: Secure remote access with split-tunnel VPN
- **Multi-Tenant Environments**: Zone-based isolation and access control
- **Internal Service Hosting**: HAProxy reverse proxy with SSL termination
- **Zero-Trust Architecture**: Explicit firewall rules and network segmentation
- **Compliance Requirements**: Centralized logging and certificate management

---

## ✨ Key Features

| Feature | Description | Benefit |
|---------|-------------|---------|
| **Centralized SSL/TLS Termination** | HAProxy handles all HTTPS with Let's Encrypt certificates | Single point of SSL management, simplified certificate rotation |
| **Network Segmentation** | Four isolated zones (WAN, DMZ, LAN, VPN) | Defense in depth, blast radius containment |
| **Split-Tunnel VPN** | Remote users access internal resources without routing all traffic | Reduced latency, lower bandwidth consumption, improved performance |
| **Internal DNS with Split-Horizon** | Unbound resolver with AD integration | Seamless internal/external name resolution |
| **Automatic Certificate Management** | Let's Encrypt integration with renewal automation | Zero-trust SSL, reduced operational overhead |
| **Advanced Firewall Policies** | Explicit zone-to-zone rules with logging | Audit trails, compliance ready |
| **High-Availability Ready** | Designed for HA clustering | Business continuity support |

---

## 🏗️ Architecture

### Network Topology

```
┌─────────────────────────────────────────────────────────────────┐
│                         INTERNET / WAN                          │
└─────────────────┬───────────────────────────────┬───────────────┘
                  │ HTTPS (443)                   │ UDP (1194)
                  │                               │
        ┌─────────▼───────────────────────────────▼─────────┐
        │                                                     │
        │         🔥 OPNsense Firewall / Router 🔥          │
        │                                                     │
        │  ┌──────────────┐    ┌──────────────────┐          │
        │  │  HAProxy     │    │  OpenVPN Server  │          │
        │  │ (SSL Term.)  │    │ (Split-Tunnel)   │          │
        │  └──────┬───────┘    └────────┬─────────┘          │
        │         │                     │                     │
        │  ┌──────▼──────────────────────▼──────┐             │
        │  │   Unbound DNS Resolver             │             │
        │  │   (Split-Horizon Resolution)       │             │
        │  └──────────────────────────────────┬─┘             │
        └─────────────────────────┬───────────┼───────────────┘
                                  │           │
                ┌─────────────────▼──┐    ┌──▼──────────────────┐
                │  LAN Zone           │    │  DMZ Zone          │
                │  10.0.10.0/24       │    │  10.0.20.0/24      │
                │                     │    │                    │
                │ • Active Directory  │    │ • Web Servers      │
                │ • File Servers      │    │ • Mail Gateway     │
                │ • Workstations      │    │ • DNS Auth Server  │
                │ • Applications      │    │ • Monitoring       │
                └─────────────────────┘    └────────────────────┘
                          ▲                          ▲
                          │                          │
                ┌─────────▼──────────────────────────▼──────────┐
                │  VPN Zone (OpenVPN Clients)                    │
                │  10.0.30.0/24                                  │
                │  Remote Workers & Contractors                  │
                └──────────────────────────────────────────────┘
```

### Zone Configuration

| Zone | Subnet | Primary Use | Example Hosts |
|------|--------|-------------|----------------|
| **WAN** | Public IP | Internet connectivity & SSL termination | - |
| **DMZ** | 10.0.20.0/24 | Public-facing services | mail.corp.local, web.corp.local, ns-ext.corp.local |
| **LAN** | 10.0.10.0/24 | Internal systems & services | dc.corp.local, fs.corp.local, workstations |
| **VPN** | 10.0.30.0/24 | Remote authenticated users | vpn clients (assigned dynamically) |

### Core Components

| Component | Role | Version | Notes |
|-----------|------|---------|-------|
| **OPNsense** | Core firewall, router, service host | 22+ | FreeBSD-based, community edition sufficient |
| **HAProxy Plugin** | SSL termination, reverse proxy, load balancing | 2.4+ | Handles all HTTPS traffic |
| **Unbound DNS** | Internal recursive resolver | 1.13+ | Split-horizon DNS, upstream forwarding |
| **Let's Encrypt Plugin** | Automated SSL certificate management | - | DNS-01 validation recommended |
| **OpenVPN** | Split-tunnel VPN access | 2.5+ | Per-user certificates, MFA capable |
| **Windows AD DNS** | Internal domain authority (optional) | 2016+ | Hosts corp.local zone, forwarders to Unbound |

---

## 📋 Prerequisites

### Hardware Requirements

- **Minimum**: 2+ CPU cores, 4GB RAM, 20GB storage
- **Recommended**: 4+ cores, 8GB+ RAM, 50GB+ SSD for HA/clustering
- **Network**: 3+ NICs (WAN, LAN, DMZ) or 4+ for separate VPN interface

### Software Requirements

- OPNsense 22.0 or later (community or business edition)
- HAProxy plugin (available in OPNsense package manager)
- Let's Encrypt plugin (available in OPNsense package manager)
- OpenVPN plugin (pre-installed)

### Access Requirements

- Local console access for initial setup
- Outbound HTTPS (443) for Let's Encrypt validation
- DNS access for DNS-01 challenge (if using DNS validation)

### Domain & Certificate Prerequisites

- A public domain (e.g., `exampledomain.com`) with DNS control
- Valid email for Let's Encrypt registration
- DNS provider supporting API access (for automated DNS-01 challenges)

---

## 🚀 Quick Start

### Step 1: Initial OPNsense Installation

1. Download OPNsense ISO from [opnsense.org](https://opnsense.org/download/)
2. Create bootable media and install on your firewall appliance
3. Configure WAN, LAN, and DMZ network interfaces during installation
4. Access the WebUI at `https://<LAN_IP>` (default credentials: root/opnsense)

### Step 2: Enable Plugins

```bash
# Via WebUI: System → Firmware → Plugins
# Install the following:
- os-haproxy
- os-acme-client (Let's Encrypt)
- os-openvpn
```

### Step 3: Configure Basic Network Zones

1. Navigate to **Interfaces → Assignments**
2. Create zones: WAN, LAN, DMZ, VPN
3. Assign IP addresses per zone configuration table above
4. Enable each interface

### Step 4: Deploy SSL Certificates

1. Go to **System → ACME Certificates**
2. Create new Let's Encrypt account
3. Configure DNS provider API credentials
4. Create certificate for `*.exampledomain.com` (wildcard)
5. Enable automatic renewal (set to run monthly)

### Step 5: Configure HAProxy

See [HAProxy Configuration](#-ssl-termination-haproxy) section below.

### Step 6: Setup OpenVPN Server

See [OpenVPN Configuration](#-split-tunnel-vpn-openvpn) section below.

### Step 7: Configure DNS

See [DNS Configuration](#-internal-dns-with-split-horizon) section below.

### Step 8: Apply Firewall Rules

See [Firewall Policies](#-firewall-policy-matrix) section below.

---

## ⚙️ Configuration Guide

### 🔒 SSL Termination (HAProxy)

HAProxy acts as the primary HTTPS endpoint, terminating all SSL/TLS connections and forwarding decrypted traffic to internal backend services.

#### Frontend Configuration

| Setting | Value | Purpose |
|---------|-------|---------|
| **Name** | Public-HTTPS | Logical identifier |
| **Interface** | WAN, DMZ | Listen on multiple zones |
| **Port** | 443 | Standard HTTPS port |
| **Certificate** | Let's Encrypt (Wildcard) | SSL certificate for *.exampledomain.com |
| **SSL Options** | HTTPS / SSL Offloading | Terminate TLS connections |
| **Default Backend** | Select based on hostname | Route traffic to correct backend |

#### Backend Configuration

```yaml
Backend: internal-mail-server
  Name: Internal Mail (10.0.20.5)
  Server Address: 10.0.20.5
  Port: 443
  SSL Check: Enabled
  Health Check: HTTP(S) GET /status
  Check Interval: 5s
  
Backend: internal-web-server
  Name: Internal Web (10.0.20.10)
  Server Address: 10.0.20.10
  Port: 8443
  SSL Check: Enabled
  Health Check: HTTP(S) GET /health
  Check Interval: 10s
```

#### Hostname Routing (ACL/Rules)

```
Rule: mail traffic
  Condition: Host matches mail.exampledomain.com
  Action: Route to internal-mail-server

Rule: web traffic
  Condition: Host matches web.exampledomain.com
  Action: Route to internal-web-server
```

**Result**: All HTTPS requests are decrypted at OPNsense → inspected → forwarded internally → responses encrypted → sent to client. One SSL certificate manages all hostnames.

---

### 🌐 Internal DNS with Split-Horizon

#### Unbound Resolver (OPNsense)

| Setting | Configuration |
|---------|---------------|
| **Listen Interfaces** | LAN, DMZ, VPN zones |
| **Outbound Interface** | WAN (for upstream queries) |
| **Forwarding Mode** | Enabled |
| **Upstream DNS** | 1.1.1.1 (Cloudflare), 8.8.8.8 (Google) |
| **Local Zone** | corp.local (transparent for internal domains) |
| **Domain Overrides** | corp.local → 10.0.10.5 (AD DNS server) |

#### Active Directory DNS (Optional - Windows 2016+)

Configure your AD DNS server to forward external queries to OPNsense:

```dns
; Active Directory DNS Server Configuration
; Zone: corp.local (Authoritative)
; Forwarders: 10.0.1.1 (OPNsense Unbound)

; Example Records:
dc.corp.local        IN  A  10.0.10.5
mail.corp.local      IN  A  10.0.20.1
fs.corp.local        IN  A  10.0.10.10
vpn.corp.local       IN  A  10.0.1.1
_ldap._tcp.corp.local IN SRV 0 100 389 dc.corp.local
```

#### DNS Resolution Flow

```
Internal Client (10.0.10.x)
    ↓ Query: mail.corp.local
OPNsense Unbound DNS
    ↓ Check local zone override
Active Directory DNS Server (10.0.10.5)
    ↓ Authoritative response
Client receives: 10.0.20.1
    
External Query (e.g., google.com)
OPNsense Unbound
    ↓ Not in local zones, forward upstream
Cloudflare DNS (1.1.1.1)
    ↓ Response
Client receives: [IP address]
```

---

### 🧾 Split-Tunnel VPN (OpenVPN)

Split-tunnel VPN allows remote users to access internal resources without routing all internet traffic through the VPN tunnel, improving performance and reducing bandwidth.

#### Server Configuration

| Setting | Value | Rationale |
|---------|-------|-----------|
| **Role** | Server | Centralized access point |
| **Protocol** | UDP | Lower latency than TCP |
| **Port** | 1194 | Standard OpenVPN port |
| **Device Type** | tun | Tunnel device (layer 3) |
| **Server Network** | 10.0.30.0/24 | Dedicated VPN zone |
| **Local Networks** | 10.0.10.0/24, 10.0.20.0/24 | Routes pushed to clients |
| **Redirect Gateway** | ❌ Disabled | Split-tunnel (critical!) |
| **Certificate** | VPN-Server | Server-side certificate |
| **Client Certificate** | Required | Per-user authentication |
| **Cipher** | AES-256-GCM | Military-grade encryption |
| **Auth Digest** | SHA256 | HMAC authentication |
| **TLS Key** | tls-crypt | Additional TLS layer protection |
| **TLS Min Version** | 1.2 | Modern TLS only |
| **Keepalive** | 10 60 | Maintain connection during inactivity |
| **Renegotiate** | 3600s | Re-authenticate hourly |

#### Advanced Configuration (Server Push Options)

```openvpn
# Define routes for split-tunnel (internal networks only)
push "route 10.0.10.0 255.255.255.0"
push "route 10.0.20.0 255.255.255.0"

# DNS configuration
push "dhcp-option DOMAIN corp.local"
push "dhcp-option DNS 10.0.10.1"

# Security hardening
push "cipher AES-256-GCM"
push "auth SHA256"

# Client-side settings
push "tls-version-min 1.2"
push "comp-lzo no"  # Disable compression (CRIME protection)

# Keepalive settings
push "keepalive 10 60"
push "explicit-exit-notify 1"
```

#### Client Export & Distribution

| Option | Setting | Purpose |
|--------|---------|---------|
| **Hostname** | vpn.exampledomain.com | Public VPN endpoint |
| **Port** | 1194 | Match server port |
| **Protocol** | UDP | Match server protocol |
| **Use Random Port** | ✅ Enabled | Avoid detection/blocking |
| **Validate Subject** | ✅ Enabled | Prevent MITM attacks |
| **Password Save** | ❌ Disabled | Security: no plaintext passwords |
| **OTP Challenge** | ✅ Optional | Multi-factor authentication |

#### Client Configuration Example (.ovpn profile)

```openvpn
client
remote vpn.exampledomain.com 1194 udp
proto udp
dev tun
resolv-retry infinite
nobind

# Split-tunnel routes (only internal networks)
route 10.0.10.0 255.255.255.0
route 10.0.20.0 255.255.255.0

# DNS
dhcp-option DOMAIN corp.local
dhcp-option DNS 10.0.10.1

# Security
tls-version-min 1.2
cipher AES-256-GCM
auth SHA256
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305

# Keepalive & timeouts
keepalive 10 60
explicit-exit-notify 1
comp-lzo no

# Certificates (embedded)
<ca>
[Certificate content]
</ca>

<cert>
[User certificate]
</cert>

<key>
[Private key]
</key>

<tls-crypt>
[TLS key]
</tls-crypt>
```

**How to Deploy**: Clients download their personalized .ovpn profile from OPNsense Web UI or via secure link. Each user receives a unique certificate.

---

### 🧱 Firewall Policy Matrix

Explicit allow-list firewall rules provide defense-in-depth and ensure only authorized traffic flows between zones.

| From | To | Ports | Protocol | Action | Logging | Purpose |
|------|-----|-------|----------|--------|---------|---------|
| **WAN** | OPNsense | 443 | TCP | ✅ Allow | Yes | HTTPS (HAProxy) |
| **WAN** | OPNsense | 1194 | UDP | ✅ Allow | Yes | OpenVPN access |
| **WAN** | * | Any | Any | ❌ Deny | Yes | Default: Drop all inbound |
| **LAN** | LAN | Any | Any | ✅ Allow | No | Internal LAN traffic |
| **LAN** | DMZ | 53,443,445 | TCP/UDP | ✅ Allow | Yes | DNS, HTTPS, SMB |
| **LAN** | WAN | Any | Any | ✅ Allow | No | Outbound internet |
| **DMZ** | LAN | Any | Any | ❌ Deny | Yes | **Critical**: Isolate DMZ from LAN |
| **DMZ** | WAN | 80,443 | TCP | ✅ Allow | Yes | Outbound web services |
| **DMZ** | OPNsense | 53 | UDP | ✅ Allow | No | DNS queries |
| **VPN** | LAN | 53,445,443,3389 | TCP/UDP | ✅ Allow | Yes | DNS, SMB, RDP to LAN |
| **VPN** | DMZ | 443,8443 | TCP | ✅ Allow | Yes | HTTPS to web servers |
| **VPN** | WAN | Any | Any | ❌ Deny | Yes | **Critical**: No direct internet (split-tunnel) |
| **VPN** | OPNsense | 53 | UDP | ✅ Allow | No | DNS queries |

**Policy Notes**:
- All rules logged for audit/compliance
- Default-deny posture: explicit allow only
- DMZ and LAN isolation enforced
- VPN clients cannot route internet (split-tunnel)

---

### 🔑 Authentication & Multi-Factor Authentication (MFA)

| Setting | Value | Description |
|---------|-------|-------------|
| **VPN Auth Backend** | Local User Database | OPNsense built-in users + groups |
| **MFA Type** | TOTP (Time-based OTP) | Authenticator apps (Google, Authy, etc.) |
| **MFA Status** | Optional | Can be enforced per user/group |
| **Certificate CN Matching** | Strict | Username must match certificate CN |
| **Session Timeout** | 86400s (24h) | Automatic re-authentication |
| **Renegotiation** | 3600s (1h) | Periodic credential refresh |

#### Enabling TOTP for VPN Users

1. System → Access → Servers → TOTP → Enable
2. Create user: System → Access → Users
3. Generate TOTP secret
4. Share secret (QR code) with user
5. User enrolls in authenticator app
6. Test login with username + password + 6-digit OTP

---

## 🛡️ Security Best Practices

### SSL/TLS Security

- ✅ Enforce TLS 1.2 minimum (no TLS 1.0/1.1)
- ✅ Use AES-256-GCM cipher for VPN
- ✅ Enable Perfect Forward Secrecy (PFS) in HAProxy
- ✅ Auto-renew certificates 30 days before expiry
- ✅ Implement OCSP stapling for certificate validation
- ✅ Use wildcard or multi-SAN certificates to minimize scope

### Network Segmentation

- ✅ Maintain strict DMZ ↔ LAN isolation
- ✅ Default-deny firewall posture
- ✅ Log all inter-zone traffic
- ✅ Implement egress filtering (DMZ → internet only on 80/443)
- ✅ Segment internal services (separate subnets where possible)

### VPN Hardening

- ✅ Split-tunnel enabled (never full-tunnel without justification)
- ✅ Disable compression (CRIME attack protection)
- ✅ Per-user certificates with short validity (90-180 days)
- ✅ Strict CN validation (username ↔ certificate match)
- ✅ MFA required for all VPN access
- ✅ Implement idle timeout (15-30 minutes)
- ✅ Monitor VPN logs for failed authentication attempts

### DNS Security

- ✅ DNSSEC validation enabled in Unbound
- ✅ Disable DNS recursion for external queries
- ✅ Rate-limit DNS responses (anti-amplification)
- ✅ Split-horizon for internal/external domains
- ✅ DNS forwarders hardened (use reputable providers)

### Operational Security

- ✅ Enable OPNsense SSH (key-based auth, non-standard port)
- ✅ Disable SNMP or restrict to trusted hosts only
- ✅ Centralized logging (syslog to external server)
- ✅ Regular backups of OPNsense configuration
- ✅ Patch management & software updates (monthly minimum)
- ✅ Monitor system logs for anomalies
- ✅ Implement IDS/IPS for threat detection

### Certificate Management

- ✅ Use DNS-01 challenge (less risky than HTTP-01)
- ✅ Automate renewal to prevent service disruption
- ✅ Monitor certificate expiry alerts
- ✅ Maintain certificate chain (root + intermediate + leaf)
- ✅ Plan for Let's Encrypt rate limits

---

## 🧪 Verification & Testing

### From a VPN Client

#### Test 1: Verify Split-Tunnel Routes

```bash
# Windows
route print | findstr "10.0"
# Expected: Only 10.0.10.0 and 10.0.20.0 routes appear

# macOS/Linux
netstat -rn | grep 10.0
# Expected: Internal routes via VPN interface only
```

#### Test 2: Verify Internal Access

```bash
# Ping internal server
ping 10.0.10.10

# Expected: Responses from internal LAN server
# If failed: Check firewall rules, VPN configuration
```

#### Test 3: Verify DNS Resolution

```bash
# Query internal domain
nslookup internal.corp.local
# or
dig +short internal.corp.local

# Expected: Resolves to internal IP (e.g., 10.0.20.5)
```

#### Test 4: Verify Split-Tunnel (Internet Traffic Stays Local)

```bash
# Trace route to external IP
tracert 8.8.8.8    # Windows
traceroute 8.8.8.8 # macOS/Linux

# Expected: First hop is local gateway, NOT VPN server
# If all hops go through VPN: Redirect Gateway may be enabled
```

#### Test 5: Test SMB/File Access (if applicable)

```bash
# Windows
net use \\fs.corp.local\share /user:corp.local\username password

# Expected: Drive maps successfully, files accessible
```

#### Test 6: Monitor VPN Server

```bash
# SSH to OPNsense
ssh -p 22022 root@10.0.1.1

# View VPN connections
tail -f /var/log/openvpn/openvpn.log

# Expected: Client connects, pulls route configuration, stays connected
```

### From a Browser (HAProxy Testing)

1. Navigate to `https://web.exampledomain.com`
2. Verify SSL certificate is valid (Let's Encrypt)
3. Check backend server responds correctly
4. Verify HTTPS connection succeeds without warnings

### Certificate Validation

```bash
# Verify Let's Encrypt certificate
openssl s_client -connect vpn.exampledomain.com:443 -showcerts

# Expected: Certificate chain includes Let's Encrypt root CA
```

---

## 🐛 Troubleshooting

### VPN Client Cannot Connect

**Symptom**: `Connection refused` or `timeout`

**Solutions**:
1. Check firewall rule: WAN → 1194/UDP allowed?
2. Verify OpenVPN service running: Status → Services → OpenVPN
3. Check port forwarding if OPNsense is behind NAT
4. Review OpenVPN logs: `/var/log/openvpn/openvpn.log`

### VPN Connected but No Routing

**Symptom**: VPN connects but cannot ping internal servers

**Solutions**:
1. Verify routes pushed to client: `route print`
2. Check firewall rule: VPN → LAN allowed?
3. Verify internal server firewalls allow VPN subnet
4. Test from OPNsense console: `ping 10.0.30.x`

### DNS Not Resolving

**Symptom**: `Cannot resolve corp.local`

**Solutions**:
1. Verify Unbound service running
2. Check DNS override configured: Services → Unbound DNS → Overrides
3. Verify DNS forwarder IP is correct
4. Test from OPNsense: `drill corp.local @127.0.0.1`

### HAProxy Backend Down

**Symptom**: `503 Service Unavailable` or `502 Bad Gateway`

**Solutions**:
1. Check backend server is online
2. Verify firewall rule: HAProxy → Backend allowed
3. Check backend certificate if SSL check enabled
4. Review HAProxy stats page: Status → HAProxy → Stats

### Let's Encrypt Certificate Renewal Fails

**Symptom**: Certificate expires, renewal did not occur

**Solutions**:
1. Check ACME logs: System → ACME Certificates → Log
2. Verify DNS provider API credentials
3. Ensure outbound HTTPS (443) available
4. Test DNS-01 challenge manually via DNS provider

---

## 📚 Additional Resources

- [OPNsense Official Documentation](https://docs.opnsense.org/)
- [HAProxy Configuration Manual](https://www.haproxy.org/#docs)
- [Unbound DNS Documentation](https://www.nlnetlabs.nl/projects/unbound/)
- [OpenVPN Community](https://openvpn.net/)
- [Let's Encrypt Rate Limits](https://letsencrypt.org/docs/rate-limits/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork this repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -m 'Add improvement'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Open a Pull Request with detailed description

For bug reports, please open an issue with:
- OPNsense version
- Configuration summary
- Error logs/screenshots
- Steps to reproduce

---

## ⚠️ Disclaimer

This configuration is provided as a reference implementation. While tested in production environments, every network is unique. Please:

- **Test thoroughly** before deploying to production
- **Validate security** with your security team
- **Review all settings** for your specific requirements
- **Maintain backups** of configurations
- **Monitor continuously** after deployment
- **Follow principle of least privilege** in all policies

---

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

---

## 📞 Support & Questions

For questions or issues:
- 📖 Check [Troubleshooting](#troubleshooting) section
- 🔍 Review [OPNsense Documentation](https://docs.opnsense.org/)
- 💬 Open an [GitHub Issue](issues)
- 🌐 Visit [OPNsense Forum](https://forum.opnsense.org/)

---

**Last Updated**: November 2025 | **Maintained by**: Network Infrastructure Team | **Status**: ✅ Production Ready
