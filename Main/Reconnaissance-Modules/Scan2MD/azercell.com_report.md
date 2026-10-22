# Recon Report: azercell.com
**Generated:** 2026-10-08 10:49:13 UTC  
**Modules:** metadata, dns, tls, whois, headers, tech, social, subdomains, wayback, email

---
## Table of Contents
- [Scan Metadata](#scan-metadata)
- [DNS](#dns)
- [TLS / SSL](#tls--ssl)
- [WHOIS](#whois)
- [HTTP Security Headers](#http-security-headers)
- [Technology Fingerprinting](#technology-fingerprinting)
- [Social & Metadata](#social--metadata)
- [Subdomain Enumeration](#subdomain-enumeration)
- [Wayback Machine](#wayback-machine)
- [Email Security](#email-security)

---

## Scan Metadata

| ID | Target               | Timestamp                        | Source File                  |
| -- | -------------------- | -------------------------------- | ---------------------------- |
| 1  | azercell.com         | 2026-10-08T14:44:34.405440       | tech_fingerprint.json        |
| 2  | https://azercell.com | 2026-10-08T14:44:42.118552       | social_metadata_results.json |
| 3  | azercell.com         | 2026-10-08T10:44:30.185226+00:00 | dns_enum.json                |
| 4  | azercell.com         | 2026-10-08T10:46:22.730020+00:00 | subdomains_enum.json         |
| 5  | azercell.com         | 2026-10-08T14:47:50.098074       | email_infra.json             |


---

## DNS

### DNS Records

| Type | TTL  | Value                                                                                                                                                                                                                                                   |
| ---- | ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A    | 2795 | 5.191.90.102                                                                                                                                                                                                                                            |
| MX   | 3600 | 15 smtp2.azercell.com.                                                                                                                                                                                                                                  |
| MX   | 3600 | 5 smtp1.azercell.com.                                                                                                                                                                                                                                   |
| NS   | 1784 | ns1.azercell.com.                                                                                                                                                                                                                                       |
| NS   | 1784 | ns2.azercell.com.                                                                                                                                                                                                                                       |
| SOA  | 3600 | ns.azercell.com. hostmaster.azercell.com. 2026100601 14400 3600 1048576 2560                                                                                                                                                                            |
| TXT  | 3600 | "google-site-verification=3vkq7U9vbLuQHCXl8E4Lv_SFXBsjMWVa1BuPJELjNqE"                                                                                                                                                                                  |
| TXT  | 3600 | "apple-domain-verification=9Xp13ML5KKHjjh6D"                                                                                                                                                                                                            |
| TXT  | 3600 | "pmofhtp0bfjovh04u5o6v7eqsh"                                                                                                                                                                                                                            |
| TXT  | 3600 | "v=spf1 ip4:217.168.177.101 ip4:5.191.90.6 ip4:5.191.90.87 ip4:5.191.90.88 a mx a:mailgw.azercell.com a:mailgw-a.azercell.com a:smtp1.azercell.com a:smtp2.azercell.com mx:azercell.com include:spf.protection.outlook.com include:_spf.anpdm.com -all" |
| TXT  | 3600 | "dtm-domain-verification=7gfvBmD-HB7UKxHDIwPOQ_hwTNTOqhi_HL4Nch2gyIQ"                                                                                                                                                                                   |
| TXT  | 3600 | "duo_sso_verification=qCknfcLuwQg5sfBB93kYLAmVl8W6NdtvJjR0gha0I5OwW4pRapEZbXVczpqKLZIt"                                                                                                                                                                 |
| TXT  | 3600 | "ernuib3go4e68bgdq9d0ombngk"                                                                                                                                                                                                                            |
| TXT  | 3600 | "facebook-domain-verification=1g7fgbc19vqidrc0mnj8pux1l12rwy"                                                                                                                                                                                           |

### Zone Transfer (AXFR)

- **Vulnerable:** No ✅

- **Error:** The DNS operation timed out.

- **SOA:** {}


### DNSSEC

- **DNSKEY:** ❌

- **DS:** ❌

- **RRSIG:** ❌

- **NSEC:** ❌

- **Chain Valid:** ❌


### Reverse DNS

| IP           | Hostname |
| ------------ | -------- |
| 5.191.90.102 |          |


### Dangling DNS Records

_No dangling records detected._


### TTL Anomalies

| Name         | Type   | TTL  | Value                                                          | Anomaly      |
| ------------ | ------ | ---- | -------------------------------------------------------------- | ------------ |
| negative_ttl | MEDIUM | 2560 |                                                                | negative_ttl |
| caa_missing  | HIGH   |      | No CAA records — any CA can issue certificates for this domain | caa_missing  |


### Module Results

| Module        | Result                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| records       | {"A": {"records": ["5.191.90.102"], "ttl": 2795}, "AAAA": {"records": [], "ttl": null}, "MX": {"records": ["15 smtp2.azercell.com.", "5 smtp1.azercell.com."], "ttl": 3600}, "NS": {"records": ["ns1.azercell.com.", "ns2.azercell.com."], "ttl": 1784}, "TXT": {"records": ["\"google-site-verification=3vkq7U9vbLuQHCXl8E4Lv_SFXBsjMWVa1BuPJELjNqE\"", "\"apple-domain-verification=9Xp13ML5KKHjjh6D\"", "\"pmofhtp0bfjovh04u5o6v7eqsh\"", "\"v=spf1 ip4:217.168.177.101 ip4:5.191.90.6 ip4:5.191.90.87 ip4:5.191.90.88 a mx a:mailgw.azercell.com a:mailgw-a.azercell.com a:smtp1.azercell.com a:smtp2.azercell.com mx:azercell.com include:spf.protection.outlook.com include:_spf.anpdm.com -all\"", "\"dtm-domain-verification=7gfvBmD-HB7UKxHDIwPOQ_hwTNTOqhi_HL4Nch2gyIQ\"", "\"duo_sso_verification=qCknfcLuwQg5sfBB93kYLAmVl8W6NdtvJjR0gha0I5OwW4pRapEZbXVczpqKLZIt\"", "\"ernuib3go4e68bgdq9d0ombngk\"", "\"facebook-domain-verification=1g7fgbc19vqidrc0mnj8pux1l12rwy\""], "ttl": 3600}, "SOA": {"records": ["ns.azercell.com. hostmaster.azercell.com. 2026100601 14400 3600 1048576 2560"], "ttl": 3600}, "CNAME": {"records": [], "ttl": null}, "SRV": {"records": [], "ttl": null}, "CAA": {"records": [], "ttl": null}, "PTR": {"records": [], "ttl": null}, "DNSKEY": {"records": [], "ttl": null}, "DS": {"records": [], "ttl": null}, "RRSIG": {"records": [], "ttl": null}, "NSEC": {"records": [], "ttl": null}, "NSEC3": {"records": [], "ttl": null}, "NSEC3PARAM": {"records": [], "ttl": null}, "CDNSKEY": {"records": [], "ttl": null}, "CDS": {"records": [], "ttl": null}, "TLSA": {"records": [], "ttl": null}, "SSHFP": {"records": [], "ttl": null}, "SMIMEA": {"records": [], "ttl": null}, "OPENPGPKEY": {"records": [], "ttl": null}, "IPSECKEY": {"records": [], "ttl": null}, "HTTPS": {"records": [], "ttl": null}, "SVCB": {"records": [], "ttl": null}, "NAPTR": {"records": [], "ttl": null}, "URI": {"records": [], "ttl": null}, "LOC": {"records": [], "ttl": null}, "HINFO": {"records": [], "ttl": null}, "RP": {"records": [], "ttl": null}, "AFSDB": {"records": [], "ttl": null}, "CERT": {"records": [], "ttl": null}, "DNAME": {"records": [], "ttl": null}, "HIP": {"records": [], "ttl": null}, "KX": {"records": [], "ttl": null}, "DHCID": {"records": [], "ttl": null}, "CSYNC": {"records": [], "ttl": null}, "ZONEMD": {"records": [], "ttl": null}, "EUI48": {"records": [], "ttl": null}, "EUI64": {"records": [], "ttl": null}, "NID": {"records": [], "ttl": null}, "L32": {"records": [], "ttl": null}, "L64": {"records": [], "ttl": null}, "LP": {"records": [], "ttl": null}, "WKS": {"records": [], "ttl": null}, "X25": {"records": [], "ttl": null}, "ISDN": {"records": [], "ttl": null}, "RT": {"records": [], "ttl": null}, "NSAP": {"records": [], "ttl": null}, "APL": {"records": [], "ttl": null}, "GPOS": {"records": [], "ttl": null}, "A6": {"records": [], "ttl": null}} |
| axfr          | {"error": "The DNS operation timed out."}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| reverse       | {"5.191.90.102": null}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| dangling      | [{"srv": "_sip._tcp.azercell.com", "target": "expresswaye.azercell.com", "port": 5061, "priority": 10, "reason": "port_unreachable"}, {"srv": "_sip._udp.azercell.com", "target": "expresswaye.azercell.com", "port": 5061, "priority": 10, "reason": "port_unreachable"}]                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| dnssec        | {"dnskey": false, "ds": false, "rrsig": false, "nsec": false, "chain_valid": false, "nsec_walk": [], "nsec3_optout": {}, "sshfp": [], "rrsig_expiry": [], "tlsa": []}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ttl_anomalies | [{"check": "negative_ttl", "minimum": 2560, "severity": "MEDIUM"}, {"check": "caa_missing", "severity": "HIGH", "detail": "No CAA records — any CA can issue certificates for this domain"}]                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |


---

## TLS / SSL

- **Target:** azercell.com:443

- **SNI:** azercell.com

- **Scanner:** TLS Scanner v0.1

- **Scan Time:** 2026-10-08T10:44:29.949418Z


### Negotiated Handshake

- **Version:** TLSv1.2

- **Cipher:** ECDHE-RSA-AES128-GCM-SHA256 (128 bits)

- **Handshake Time:** 10.32 ms

- **Session Ticket:** No


### ALPN

- **HTTP/2:** ❌

- **HTTP/1.1:** ❌



### Protocol Support

| Version | Supported | Rating     | Reason                           | Cipher                      | Bits |
| ------- | --------- | ---------- | -------------------------------- | --------------------------- | ---- |
| SSLv2   | ❌         | 🔴 CRITICAL | Broken - practical attacks exist |                             |      |
| SSLv3   | ❌         | 🔴 CRITICAL | POODLE attack                    |                             |      |
| TLSv1.0 | ❌         | ⚠️ WARN    | Deprecated by RFC 8996           |                             |      |
| TLSv1.1 | ❌         | ⚠️ WARN    | Deprecated by RFC 8996           |                             |      |
| TLSv1.2 | ✅         | ✅ PASS     | Secure                           | ECDHE-RSA-AES128-GCM-SHA256 | 128  |
| TLSv1.3 | ❌         | ✅ PASS     | Recommended                      |                             |      |


### Certificate Assessment

- **Grade:** A

- **Chain Complete:** ✅

- **Chain Trusted:** ❌


### Certificate Chain

| Role         | Subject CN                                 | Subject Org       | Issuer CN                                  | Not Before                | Not After                 | Days Left | Expired | Self-Signed | Key | Bits | Weak | Sig Alg |
| ------------ | ------------------------------------------ | ----------------- | ------------------------------------------ | ------------------------- | ------------------------- | --------- | ------- | ----------- | --- | ---- | ---- | ------- |
| leaf         | *.azercell.com                             |                   | Go Daddy Secure Certificate Authority - G2 | 2026-05-25T05:43:35+00:00 | 2026-12-09T05:43:35+00:00 | 61        | No      | No          | RSA | 2048 | No   | sha256  |
| intermediate | Go Daddy Secure Certificate Authority - G2 | GoDaddy.com, Inc. | Go Daddy Root Certificate Authority - G2   | 2011-05-03T07:00:00+00:00 | 2031-05-03T07:00:00+00:00 | 1667      | No      | No          | RSA | 2048 | No   | sha256  |


### OCSP

- **Status:** good

- **Cert Status:** None

- **Responder:** http://ocsp.godaddy.com/


### Certificate Transparency

- **CT ID:** 15056245772

- **Logged At:** None

- **Common Name:** *.azercell.com

- **Issuer:** GoDaddy

- **Total Found:** 1


### Cipher Assessment

- **Grade:** B

- **PFS Ciphers:** 12 | Non-PFS: 6

- **Strong:** None | Weak: None | Insecure: None

- **Warnings:** 6 cipher(s) without PFS supported: TLS_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA..., No TLS 1.3 cipher suites supported


### Supported Ciphers

| Name                                  | Protocol | Bits | PFS | Strength | Category   |
| ------------------------------------- | -------- | ---- | --- | -------- | ---------- |
| TLS_DHE_RSA_WITH_AES_128_CBC_SHA      | TLSv1.2  | 128  | ❌   |          | dhe_cbc    |
| TLS_DHE_RSA_WITH_AES_128_CBC_SHA256   | TLSv1.2  | 128  | ❌   |          | dhe_cbc    |
| TLS_DHE_RSA_WITH_AES_128_GCM_SHA256   | TLSv1.2  | 128  | ❌   |          | dhe_aead   |
| TLS_DHE_RSA_WITH_AES_256_CBC_SHA      | TLSv1.2  | 256  | ❌   |          | dhe_cbc    |
| TLS_DHE_RSA_WITH_AES_256_CBC_SHA256   | TLSv1.2  | 256  | ❌   |          | dhe_cbc    |
| TLS_DHE_RSA_WITH_AES_256_GCM_SHA384   | TLSv1.2  | 256  | ❌   |          | dhe_aead   |
| TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA    | TLSv1.2  | 128  | ❌   |          | ecdhe_cbc  |
| TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 | TLSv1.2  | 128  | ❌   |          | ecdhe_cbc  |
| TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | TLSv1.2  | 128  | ❌   |          | ecdhe_aead |
| TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA    | TLSv1.2  | 256  | ❌   |          | ecdhe_cbc  |
| TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 | TLSv1.2  | 256  | ❌   |          | ecdhe_cbc  |
| TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | TLSv1.2  | 256  | ❌   |          | ecdhe_aead |
| TLS_RSA_WITH_AES_128_CBC_SHA          | TLSv1.2  | 128  | ❌   |          | rsa_cbc    |
| TLS_RSA_WITH_AES_128_CBC_SHA256       | TLSv1.2  | 128  | ❌   |          | rsa_cbc    |
| TLS_RSA_WITH_AES_128_GCM_SHA256       | TLSv1.2  | 128  | ❌   |          | rsa_aead   |
| TLS_RSA_WITH_AES_256_CBC_SHA          | TLSv1.2  | 256  | ❌   |          | rsa_cbc    |
| TLS_RSA_WITH_AES_256_CBC_SHA256       | TLSv1.2  | 256  | ❌   |          | rsa_cbc    |
| TLS_RSA_WITH_AES_256_GCM_SHA384       | TLSv1.2  | 256  | ❌   |          | rsa_aead   |


### PFS Assessment

- **Grade:** B

- **Strength Level:** strong

- **Best ECDHE Group:** secp384r1 (384 bits)

- **ECDHE Strong/Obsolete/Weak:** 1/1/0

- **Custom DHE Supported:** Yes

- **Warnings:** Obsolete ECDHE curves supported: prime256v1


### PFS Key Exchange Support

- **PFS Available:** Yes

- **Supported Key Exchanges:** ECDHE, DHE

- **Non-PFS Key Exchanges:** RSA, ECDH

- **All Supported Key Exchanges:** ECDHE, DHE, RSA, ECDH

- **Unsupported Key Exchanges:** DHE_DSS, DHE_RSA, DH_DSS, DH_RSA, PSK, SRP


### PFS Groups

| Name       | Type  | Supported | Bits | Protocol | Cipher                      | Handshake (ms) | Classification | Error                                                                                             |
| ---------- | ----- | --------- | ---- | -------- | --------------------------- | -------------- | -------------- | ------------------------------------------------------------------------------------------------- |
| prime192v1 | ecdhe | ❌         |      |          |                             |                | unknown        | SSL: NO_SUITABLE_GROUPS                                                                           |
| prime256v1 | ecdhe | ✅         | 256  | TLSv1.2  | ECDHE-RSA-AES128-GCM-SHA256 | 11.01          | obsolete_ecdhe |                                                                                                   |
| secp112r1  | ecdhe | ❌         |      |          |                             |                | unknown        | Curve 'secp112r1' could not be set: not supported by this OpenSSL build                           |
| secp112r2  | ecdhe | ❌         |      |          |                             |                | unknown        | Curve 'secp112r2' could not be set: not supported by this OpenSSL build                           |
| secp128r1  | ecdhe | ❌         |      |          |                             |                | unknown        | Curve 'secp128r1' could not be set: not supported by this OpenSSL build                           |
| secp128r2  | ecdhe | ❌         |      |          |                             |                | unknown        | Curve 'secp128r2' could not be set: not supported by this OpenSSL build                           |
| secp160k1  | ecdhe | ❌         |      |          |                             |                | unknown        | SSL: NO_SUITABLE_GROUPS                                                                           |
| secp160r1  | ecdhe | ❌         |      |          |                             |                | unknown        | SSL: NO_SUITABLE_GROUPS                                                                           |
| secp160r2  | ecdhe | ❌         |      |          |                             |                | unknown        | SSL: NO_SUITABLE_GROUPS                                                                           |
| secp192r1  | ecdhe | ❌         |      |          |                             |                | unknown        | Curve 'secp192r1' could not be set: not supported by this OpenSSL build                           |
| secp224r1  | ecdhe | ❌         |      |          |                             |                | unknown        | SSL: NO_SUITABLE_GROUPS                                                                           |
| secp256k1  | ecdhe | ❌         |      |          |                             |                | unknown        | SSL: NO_SUITABLE_GROUPS                                                                           |
| secp256r1  | ecdhe | ❌         |      |          |                             |                | unknown        | Curve 'secp256r1' could not be set: not supported by this OpenSSL build                           |
| secp384r1  | ecdhe | ✅         | 384  | TLSv1.2  | ECDHE-RSA-AES128-GCM-SHA256 | 15.23          | strong_ecdhe   |                                                                                                   |
| secp521r1  | ecdhe | ❌         |      |          |                             |                | unknown        | SSL: SSLV3_ALERT_HANDSHAKE_FAILURE                                                                |
| sect113r1  | ecdhe | ❌         |      |          |                             |                | unknown        | Curve 'sect113r1' could not be set: not supported by this OpenSSL build                           |
| sect113r2  | ecdhe | ❌         |      |          |                             |                | unknown        | Curve 'sect113r2' could not be set: not supported by this OpenSSL build                           |
| sect131r1  | ecdhe | ❌         |      |          |                             |                | unknown        | Curve 'sect131r1' could not be set: not supported by this OpenSSL build                           |
| sect131r2  | ecdhe | ❌         |      |          |                             |                | unknown        | Curve 'sect131r2' could not be set: not supported by this OpenSSL build                           |
| sect163k1  | ecdhe | ❌         |      |          |                             |                | unknown        | SSL: NO_SUITABLE_GROUPS                                                                           |
| sect163r1  | ecdhe | ❌         |      |          |                             |                | unknown        | SSL: NO_SUITABLE_GROUPS                                                                           |
| sect163r2  | ecdhe | ❌         |      |          |                             |                | unknown        | SSL: NO_SUITABLE_GROUPS                                                                           |
| sect283k1  | ecdhe | ❌         |      |          |                             |                | unknown        | SSL: NO_SUITABLE_GROUPS                                                                           |
| sect283r1  | ecdhe | ❌         |      |          |                             |                | unknown        | SSL: NO_SUITABLE_GROUPS                                                                           |
| sect409k1  | ecdhe | ❌         |      |          |                             |                | unknown        | SSL: NO_SUITABLE_GROUPS                                                                           |
| sect409r1  | ecdhe | ❌         |      |          |                             |                | unknown        | SSL: NO_SUITABLE_GROUPS                                                                           |
| sect571k1  | ecdhe | ❌         |      |          |                             |                | unknown        | SSL: NO_SUITABLE_GROUPS                                                                           |
| sect571r1  | ecdhe | ❌         |      |          |                             |                | unknown        | SSL: NO_SUITABLE_GROUPS                                                                           |
| x25519     | ecdhe | ❌         |      |          |                             |                | unknown        | Curve 'x25519' could not be set: not supported by this OpenSSL build                              |
| x448       | ecdhe | ❌         |      |          |                             |                | unknown        | Curve 'x448' could not be set: not supported by this OpenSSL build                                |
| ffdhe2048  | ffdhe | ❌         |      |          |                             |                | unknown        | FFDHE group probing is unsupported by this Python/OpenSSL build; group 'ffdhe2048' was not tested |
| ffdhe3072  | ffdhe | ❌         |      |          |                             |                | unknown        | FFDHE group probing is unsupported by this Python/OpenSSL build; group 'ffdhe3072' was not tested |
| ffdhe4096  | ffdhe | ❌         |      |          |                             |                | unknown        | FFDHE group probing is unsupported by this Python/OpenSSL build; group 'ffdhe4096' was not tested |
| ffdhe6144  | ffdhe | ❌         |      |          |                             |                | unknown        | FFDHE group probing is unsupported by this Python/OpenSSL build; group 'ffdhe6144' was not tested |
| ffdhe8192  | ffdhe | ❌         |      |          |                             |                | unknown        | FFDHE group probing is unsupported by this Python/OpenSSL build; group 'ffdhe8192' was not tested |


### Cipher Preference

- **Preference Known:** Yes

- **PFS Preferred:** Yes

- **PFS Position:** 0

- **PFS Ciphers:** 15 | **Non-PFS Ciphers:** 6

| Order | Cipher                      |
| ----- | --------------------------- |
| 1     | ECDHE-RSA-AES128-GCM-SHA256 |
| 2     | ECDHE-RSA-AES128-GCM-SHA256 |
| 3     | ECDHE-RSA-AES128-GCM-SHA256 |
| 4     | ECDHE-RSA-AES256-GCM-SHA384 |
| 5     | ECDHE-RSA-AES128-GCM-SHA256 |
| 6     | ECDHE-RSA-AES256-SHA384     |
| 7     | ECDHE-RSA-AES128-SHA256     |
| 8     | ECDHE-RSA-AES256-SHA        |
| 9     | ECDHE-RSA-AES128-SHA        |
| 10    | DHE-RSA-AES256-GCM-SHA384   |
| 11    | DHE-RSA-AES128-GCM-SHA256   |
| 12    | DHE-RSA-AES256-SHA256       |
| 13    | DHE-RSA-AES128-SHA256       |
| 14    | DHE-RSA-AES256-SHA          |
| 15    | DHE-RSA-AES128-SHA          |
| 16    | AES256-GCM-SHA384           |
| 17    | AES128-GCM-SHA256           |
| 18    | AES256-SHA256               |
| 19    | AES128-SHA256               |
| 20    | AES256-SHA                  |
| 21    | AES128-SHA                  |


### ECDH Curves

- **Supported:** secp384r1, prime256v1

- **Strong:** secp384r1

- **Obsolete:** prime256v1


### Fallback / Downgrade Tests

| Vulnerability         | Vulnerable | Certainty | Detail                                                             |
| --------------------- | ---------- | --------- | ------------------------------------------------------------------ |
| fallback_scsv_missing | No ✅       | unknown   | Could not determine highest supported version; skipping SCSV check |
| sslv3_enabled         | No ✅       | safe      | SSLv3 rejected by server (alert 40).                               |
| tls10_downgrade       | No ✅       | safe      | TLSv1.0 rejected by server (alert 40).                             |
| tls11_downgrade       | No ✅       | safe      | TLSv1.1 rejected by server (alert 40).                             |


### Fallback Assessment

- **Grade:** B

- **Confirmed/Probable/Potential/Safe:** 0/0/0/3 (of 4)


### Session Resumption

- **Mode:** session_id_ticket

- **Session ID:** ✅

- **Session Ticket:** ✅


### Protocol Assessment

- **Grade:** B

- **Warnings:** TLSv1.3 not supported (recommended)

- **Notes:** HTTP/2 (h2) not advertised via ALPN


### TLS-Specific Headers

- **HSTS Present:** ❌

- **Expect-CT Present:** ❌

- **HPKP Present:** No

- **Score Grade:** F

- **Score Issues:** HSTS header is missing; Expect-CT header is missing (optional but recommended for CT enforcement)


### Network Assessment

- **Grade:** B

- **Warnings:** No CAA records published (any CA may issue certificates); No TLSA (DANE) records found for any common service port; No MTA-STS DNS record found


### DANE


### MTA-STS

- **Error:** MTA-STS policy fetch failed: [Errno 11001] getaddrinfo failed


---

## WHOIS

- **Domain:** azercell.com

- **TLD:** com

- **Queried At:** 2026-10-08 10:44:30 UTC

- **Tool:** whois-checker v2.0.0


### Registration Info

- **Created:** 1997-12-11 05:00:00 UTC

- **Updated:** 2023-12-10 05:17:05 UTC

- **Expires:** 2033-12-10 05:00:00 UTC

- **Days Until Expiry:** 2619

- **Registrar:** 2 (IANA: 2)

- **Status:** client transfer prohibited, clientTransferProhibited

- **Name Servers:** ns1.azercell.com, ns2.azercell.com

- **DNSSEC:** unsigned

- **Privacy Enabled:** No

- **Privacy Note:** No obvious privacy/redaction markers


### Contacts

| Role       | Name | Organization | Address                          | Country | Phone          | Email              |
| ---------- | ---- | ------------ | -------------------------------- | ------- | -------------- | ------------------ |
| registrant |      |              | 61a Tbilisi ave, Baku, -, AZ1122 | AZ      | +994.502100025 | smamedov@gmail.com |
| tech       |      |              |                                  |         | +994.502100025 | smamedov@gmail.com |


### RDAP Events

| Action                       | Date                    |
| ---------------------------- | ----------------------- |
| registration                 | 1997-12-11 05:00:00 UTC |
| last changed                 | 2023-12-10 05:17:05 UTC |
| last update of RDAP database | 2026-10-08 10:44:34 UTC |
| expiration                   | 2033-12-10 05:00:00 UTC |


### IP Information

| IP           | ASN   | AS Name     | ISP          | Country         | City | Hosting | Proxy/VPN | Usage  | PTR | CIDR         |
| ------------ | ----- | ----------- | ------------ | --------------- | ---- | ------- | --------- | ------ | --- | ------------ |
| 5.191.90.102 | 31721 | AZERCELL-AS | AZERCELL-LTE | Azerbaijan (AZ) | Baku | No      | No        | mobile |     | 5.191.0.0/17 |


### DNS Intelligence

| Record   | Value                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A        | ['5.191.90.102']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| NS       | ['ns1.azercell.com', 'ns2.azercell.com']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| MX       | ['5 smtp1.azercell.com', '15 smtp2.azercell.com']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| TXT      | ['ernuib3go4e68bgdq9d0ombngk', 'google-site-verification=3vkq7U9vbLuQHCXl8E4Lv_SFXBsjMWVa1BuPJELjNqE', 'duo_sso_verification=qCknfcLuwQg5sfBB93kYLAmVl8W6NdtvJjR0gha0I5OwW4pRapEZbXVczpqKLZIt', 'apple-domain-verification=9Xp13ML5KKHjjh6D', 'facebook-domain-verification=1g7fgbc19vqidrc0mnj8pux1l12rwy', 'v=spf1 ip4:217.168.177.101 ip4:5.191.90.6 ip4:5.191.90.87 ip4:5.191.90.88 a mx a:mailgw.azercell.com a:mailgw-a.azercell.com a:smtp1.azercell.com a:smtp2.azercell.com mx:azercell.com include:spf.protection.outlook.com include:_spf.anpdm.com -all', 'pmofhtp0bfjovh04u5o6v7eqsh', 'dtm-domain-verification=7gfvBmD-HB7UKxHDIwPOQ_hwTNTOqhi_HL4Nch2gyIQ'] |
| Resolver | dnspython                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |


### HTTP Probes

| URL                   | Status | Final URL             | Headers |
| --------------------- | ------ | --------------------- | ------- |
| https://azercell.com/ | 0      | https://azercell.com/ |         |
| http://azercell.com/  | 0      | http://azercell.com/  |         |


### CDN / WAF Detection

- **Behind CDN:** No

- **Note:** No CDN/WAF signatures detected


### Blacklist Check

- **Domain:** azercell.com

- **Risk Score:** 0

- **Risk Level:** clean

- **IPs Checked:** ['5.191.90.102']


### Blacklist Hits
_No blacklist hits._


### Cross-Search (Pivot)

- **Registrant Email:** smamedov@gmail.com

- **Registrant Org:** None

- **Related Domains Found:** 0


### Historical Archive

- **First Seen:** None

- **Last Seen:** None

- **Source:** None


### Historical Snapshots

| Date                    | Registrar              | Created                 | Expires                 | Status                         | Name Servers                             | Source |
| ----------------------- | ---------------------- | ----------------------- | ----------------------- | ------------------------------ | ---------------------------------------- | ------ |
| 2023-12-10 05:17:05 UTC | Network Solutions, LLC | 1997-12-11 05:00:00 UTC | 2033-12-10 05:00:00 UTC | ["client transfer prohibited"] | ["ns1.azercell.com", "ns2.azercell.com"] | rdap   |


### WHOIS Result Payload

```json
{
  "tool": "whois-checker",
  "version": "2.0.0",
  "queried_at": "2026-10-08 10:44:30 UTC",
  "domain": "azercell.com",
  "tld": "com",
  "whois": {
    "created": "1997-12-11 05:00:00 UTC",
    "updated": "2023-12-10 05:17:05 UTC",
    "expires": "2033-12-10 05:00:00 UTC",
    "days_until_expiry": 2619,
    "expiry_warning": false,
    "status": [
      "client transfer prohibited",
      "clientTransferProhibited"
    ],
    "registrar": "2",
    "registrar_iana_id": "2",
    "name_servers": [
      "ns1.azercell.com",
      "ns2.azercell.com"
    ],
    "dnssec": "unsigned",
    "contacts": {
      "registrant": {
        "address": "61a Tbilisi ave, Baku, -, AZ1122",
        "country": "AZ",
        "phone": "+994.502100025",
        "email": "smamedov@gmail.com"
      },
      "admin": {},
      "tech": {
        "phone": "+994.502100025",
        "email": "smamedov@gmail.com"
      },
      "billing": {}
    },
    "privacy": {
      "enabled": false,
      "indicators": [],
      "note": "No obvious privacy/redaction markers",
      "visible_emails": [
        "smamedov@gmail.com",
        "smamedov@gmail.com"
      ]
    },
    "sources": [
      "rdap",
      "whois:whois.verisign-grs.com",
      "whois:whois.networksolutions.com"
    ],
    "raw": "; IANA\n% IANA WHOIS server\n% for more information on IANA, visit http://www.iana.org\n% This query returned 1 object\n\nrefer:        whois.verisign-grs.com\n\ndomain:       COM\n\norganisation: VeriSign Global Registry Services\naddress:      12061 Bluemont Way\naddress:      Reston VA 20190\naddress:      United States of America (the)\n\ncontact:      administrative\nname:         Registry Customer Service\norganisation: VeriSign Global Registry Services\naddress:      12061 Bluemont Way\naddress:      Reston VA 20190\naddress:      United States of America (the)\nphone:        +1 703 925-6999\nfax-no:       +1 703 948 3978\ne-mail:       info@verisign-grs.com\n\ncontact:      technical\nname:         Registry Customer Service\norganisation: VeriSign Global Registry Services\naddress:      12061 Bluemont Way\naddress:      Reston VA 20190\naddress:      United States of America (the)\nphone:        +1 703 925-6999\nfax-no:       +1 703 948 3978\ne-mail:       info@verisign-grs.com\n\nnserver:      A.GTLD-SERVERS.NET 192.5.6.30 2001:503:a83e:0:0:0:2:30\nnserver:      B.GTLD-SERVERS.NET 192.33.14.30 2001:503:231d:0:0:0:2:30\nnserver:      C.GTLD-SERVERS.NET 192.26.92.30 2001:503:83eb:0:0:0:0:30\nnserver:      D.GTLD-SERVERS.NET 192.31.80.30 2001:500:856e:0:0:0:0:30\nnserver:      E.GTLD-SERVERS.NET 192.12.94.30 2001:502:1ca1:0:0:0:0:30\nnserver:      F.GTLD-SERVERS.NET 192.35.51.30 2001:503:d414:0:0:0:0:30\nnserver:      G.GTLD-SERVERS.NET 192.42.93.30 2001:503:eea3:0:0:0:0:30\nnserver:      H.GTLD-SERVERS.NET 192.54.112.30 2001:502:8cc:0:0:0:0:30\nnserver:      I.GTLD-SERVERS.NET 192.43.172.30 2001:503:39c1:0:0:0:0:30\nnserver:      J.GTLD-SERVERS.NET 192.48.79.30 2001:502:7094:0:0:0:0:30\nnserver:      K.GTLD-SERVERS.NET 192.52.178.30 2001:503:d2d:0:0:0:0:30\nnserver:      L.GTLD-SERVERS.NET 192.41.162.30 2001:500:d937:0:0:0:0:30\nnserver:      M.GTLD-SERVERS.NET 192.55.83.30 2001:501:b1f9:0:0:0:0:30\nds-rdata:     19718 13 2 8acbb0cd28f41250a80a491389424d341522d946b0da0c0291f2d3d771d7805a\n\nwhois:        whois.verisign-grs.com\n\nstatus:       ACTIVE\nremarks:      Registration information: http://www.verisigninc.com\n\ncreated:      1985-01-01\nchanged:      2026-03-10\nsource:       IANA\n\n\n\n; whois.verisign-grs.com\n   Domain Name: AZERCELL.COM\r\n   Registry Domain ID: 998155_DOMAIN_COM-VRSN\r\n   Registrar WHOIS Server: whois.networksolutions.com\r\n   Registrar URL: http://networksolutions.com\r\n   Updated Date: 2023-12-10T05:17:05Z\r\n   Creation Date: 1997-12-11T05:00:00Z\r\n   Registry Expiry Date: 2033-12-10T05:00:00Z\r\n   Registrar: Network Solutions, LLC\r\n   Registrar IANA ID: 2\r\n   Registrar Abuse Contact Email: domain.operations@web.com\r\n   Registrar Abuse Contact Phone: +1.8777228662\r\n   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\r\n   Name Server: NS1.AZERCELL.COM\r\n   Name Server: NS2.AZERCELL.COM\r\n   DNSSEC: unsigned\r\n   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/\r\n>>> Last update of whois database: 2026-10-08T10:44:19Z <<<\r\n\r\nFor more information on Whois status codes, please visit https://icann.org/epp\r\n\r\nNOTICE: The expiration date displayed in this record is the date the\r\nregistrar's sponsorship of the domain name registration in the registry is\r\ncurrently set to expire. This date does not necessarily reflect the expiration\r\ndate of the domain name registrant's agreement with the sponsoring\r\nregistrar.  Users may consult the sponsoring registrar's Whois database to\r\nview the registrar's reported date of expiration for this registration.\r\n\r\nTERMS OF USE: You are not authorized to access or query our Whois\r\ndatabase through the use of electronic processes that are high-volume and\r\nautomated except as reasonably necessary to register domain names or\r\nmodify existing registrations; the Data in VeriSign Global Registry\r\nServices' (\"VeriSign\") Whois database is provided by VeriSign for\r\ninformation purposes only, and to assist persons in obtaining information\r\nabout or related to a domain name registration record. VeriSign does not\r\nguarantee its accuracy. By submitting a Whois query, you agree to abide\r\nby the following terms of use: You agree that you may use this Data only\r\nfor lawful purposes and that under no circumstances will you use this Data\r\nto: (1) allow, enable, or otherwise support the transmission of mass\r\nunsolicited, commercial advertising or solicitations via e-mail, telephone,\r\nor facsimile; or (2) enable high volume, automated, electronic processes\r\nthat apply to VeriSign (or its computer systems). The compilation,\r\nrepackaging, dissemination or other use of this Data is expressly\r\nprohibited without the prior written consent of VeriSign. You agree not to\r\nuse electronic processes that are automated and high-volume to access or\r\nquery the Whois database except as reasonably necessary to register\r\ndomain names or modify existing registrations. VeriSign reserves the right\r\nto restrict your access to the Whois database in its sole discretion to ensure\r\noperational stability.  VeriSign may restrict or terminate your access to the\r\nWhois database for failure to abide by these terms of use. VeriSign\r\nreserves the right to modify these terms at any time.\r\n\r\nThe Registry database contains ONLY .COM, .NET, .EDU domains and\r\nRegistrars.\r\n\n\n; whois.networksolutions.com\nDomain Name: AZERCELL.COM\nRegistry Domain ID: 998155_DOMAIN_COM-VRSN\nRegistrar WHOIS Server: whois.networksolutions.com\nRegistrar URL: http://networksolutions.com\nUpdated Date: 2023-12-10T05:17:52Z\nCreation Date: 1997-12-11T05:00:00Z\nRegistrar Registration Expiration Date: 2033-12-10T05:00:00Z\nRegistrar: Network Solutions, LLC\nRegistrar IANA ID: 2\nReseller: \nDomain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\nRegistry Registrant ID: \nRegistrant Name: \nRegistrant Organization: \nRegistrant Street: 61a Tbilisi ave\nRegistrant City: Baku\nRegistrant State/Province: -\nRegistrant Postal Code: AZ1122\nRegistrant Country: AZ\nRegistrant Phone: +994.502100025\nRegistrant Phone Ext: \nRegistrant Fax: +994.124981070\nRegistrant Fax Ext: \nRegistrant Email: smamedov@gmail.com\nRegistry Admin ID: \nRegistry Tech ID: \nTech Name: \nTech Phone: +994.502100025\nTech Email: smamedov@gmail.com\nName Server: NS1.AZERCELL.COM\nName Server: NS2.AZERCELL.COM\nDNSSEC: unsigned\nRegistrar Abuse Contact Email: domain.operations@web.com\nRegistrar Abuse Contact Phone: +1.8777228662\nURL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/\n>>> Last update of WHOIS database: 2026-10-08T10:44:34Z <<<\n\nFor more information on Whois status codes, please visit https://www.icann.org/resources/pages/epp-status-codes-2014-06-16-en\nThe data in Networksolutions.com's WHOIS database is provided to you by\nNetworksolutions.com for information purposes only, that is, to assist you in\nobtaining information about or related to a domain name registration\nrecord. Networksolutions.com makes this information available \"as is,\" and\ndoes not guarantee its accuracy. By submitting a WHOIS query, you\nagree that you will use this data only for lawful purposes and that,\nunder no circumstances will you use this data to: (1) allow, enable,\nor otherwise support the transmission of mass unsolicited, commercial\nadvertising or solicitations via direct mail, electronic mail, or by\ntelephone; or (2) enable high volume, automated, electronic processes\nthat apply to Networksolutions.com  (or its systems). The compilation,\nrepackaging, dissemination or other use of this data is expressly\nprohibited without the prior written consent of Networksolutions.com.\nNetworksolutions.com reserves the right to modify these terms at any time.\nBy submitting this query, you agree to abide by these terms.\nFor more information on Whois status codes, please visit\nhttps://www.icann.org/resources/pages/epp-status-codes-2014-06-16-en."
  },
  "dns": {
    "a": [
      "5.191.90.102"
    ],
    "aaaa": [],
    "ns": [
      "ns1.azercell.com",
      "ns2.azercell.com"
    ],
    "mx": [
      "5 smtp1.azercell.com",
      "15 smtp2.azercell.com"
    ],
    "cname": [],
    "txt": [
      "ernuib3go4e68bgdq9d0ombngk",
      "google-site-verification=3vkq7U9vbLuQHCXl8E4Lv_SFXBsjMWVa1BuPJELjNqE",
      "duo_sso_verification=qCknfcLuwQg5sfBB93kYLAmVl8W6NdtvJjR0gha0I5OwW4pRapEZbXVczpqKLZIt",
      "apple-domain-verification=9Xp13ML5KKHjjh6D",
      "facebook-domain-verification=1g7fgbc19vqidrc0mnj8pux1l12rwy",
      "v=spf1 ip4:217.168.177.101 ip4:5.191.90.6 ip4:5.191.90.87 ip4:5.191.90.88 a mx a:mailgw.azercell.com a:mailgw-a.azercell.com a:smtp1.azercell.com a:smtp2.azercell.com mx:azercell.com include:spf.protection.outlook.com include:_spf.anpdm.com -all",
      "pmofhtp0bfjovh04u5o6v7eqsh",
      "dtm-domain-verification=7gfvBmD-HB7UKxHDIwPOQ_hwTNTOqhi_HL4Nch2gyIQ"
    ],
    "resolver": "dnspython"
  },
  "ips": [
    {
      "ip": "5.191.90.102",
      "asn": 31721,
      "as_name": "AZERCELL-AS",
      "org": null,
      "isp": "AZERCELL-LTE",
      "country": "Azerbaijan",
      "country_code": "AZ",
      "city": "Baku",
      "region": "Baku City",
      "lat": 40.3771,
      "lon": 49.8875,
      "timezone": "Asia/Baku",
      "hosting": false,
      "proxy_or_vpn": false,
      "mobile": true,
      "usage_type": "mobile",
      "ptr": null,
      "rdap_country": "AZ",
      "cidr": "5.191.0.0/17",
      "rdap_range": "5.191.0.0 - 5.191.127.255",
      "rdap_remarks": [],
      "source": [
        "ip-api",
        "rdap"
      ]
    }
  ],
  "cdn": {
    "behind_cdn": false,
    "vendors": [],
    "evidence": {},
    "note": "No CDN/WAF signatures detected"
  },
  "cdn_advanced": {
    "behind_cdn": false,
    "vendors": [],
    "evidence": {},
    "waf_detected": [],
    "anycast": false,
    "note": "No CDN/WAF signatures detected"
  },
  "http": [
    {
      "url": "https://azercell.com/",
      "status": 0,
      "final_url": "https://azercell.com/",
      "headers": {}
    },
    {
      "url": "http://azercell.com/",
      "status": 0,
      "final_url": "http://azercell.com/",
      "headers": {}
    }
  ],
  "blacklist": {
    "domain": "azercell.com",
    "ips_checked": [
      "5.191.90.102"
    ],
    "score": 0,
    "risk": "clean",
    "hits": [],
    "checked": [
      "Abuse.ch DRONE",
      "Abuse.ch Feodo",
      "Barracuda",
      "HostKarma",
      "PSBL",
      "SORBS",
      "SURBL Multi",
      "SpamCop",
      "Spamhaus DBL",
      "Spamhaus ZEN",
      "URIBL"
    ],
    "errors": []
  },
  "cross_search": {
    "domain": "azercell.com",
    "pivots_used": [],
    "registrant_email": "smamedov@gmail.com",
    "registrant_org": null,
    "nameservers": [
      "ns1.azercell.com",
      "ns2.azercell.com"
    ],
    "ips_pivoted": [],
    "related_count": 0,
    "related_domains": [],
    "errors": []
  },
  "historical": {
    "domain": "azercell.com",
    "rdap_events": [
      {
        "action": "registration",
        "date": "1997-12-11 05:00:00 UTC"
      },
      {
        "action": "expiration",
        "date": "2033-12-10 05:00:00 UTC"
      },
      {
        "action": "last changed",
        "date": "2023-12-10 05:17:05 UTC"
      },
      {
        "action": "last update of RDAP database",
        "date": "2026-10-08 10:44:34 UTC"
      }
    ],
    "snapshots": [
      {
        "date": "2023-12-10 05:17:05 UTC",
        "registrar": "Network Solutions, LLC",
        "created": "1997-12-11 05:00:00 UTC",
        "expires": "2033-12-10 05:00:00 UTC",
        "status": [
          "client transfer prohibited"
        ],
        "name_servers": [
          "ns1.azercell.com",
          "ns2.azercell.com"
        ],
        "source": "rdap"
      }
    ],
    "archive": null,
    "errors": []
  },
  "errors": []
}
```


---

## HTTP Security Headers

- **Domain:** azercell.com

- **URL:** https://azercell.com

- **Final URL:** None

- **Status Code:** None

- **Grade:** F

- **Score:** 51.0

- **Records Read:** 70 | Responses Analyzed: 70


### Findings Summary

| Module                             | Severity | Header                              | Detail                                                                                                                                                                                                   | Count |
| ---------------------------------- | -------- | ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----- |
| Security Headers Analyzer          | 🟠 HIGH   | Content-Security-Policy             | Header is missing                                                                                                                                                                                        | 70    |
| Security Headers Analyzer          | 🟠 HIGH   | Strict-Transport-Security           | Header is missing                                                                                                                                                                                        | 68    |
| Security Headers Analyzer          | 🟠 HIGH   | X-Frame-Options                     | Header is missing; page may be vulnerable to clickjacking                                                                                                                                                | 65    |
| Cache Control Analyzer             | 🟠 HIGH   | Cache-Control                       | public directive on a sensitive response — shared caches and proxies may store this content                                                                                                              | 12    |
| Cookie & JWT Analyzer              | 🟡 MEDIUM | Set-Cookie (TS0d265b7a027)          | Secure flag is missing on a cookie set over HTTPS; it can be sent over a future plaintext HTTP connection and intercepted                                                                                | 67    |
| Security Headers Analyzer          | 🟡 MEDIUM | X-Content-Type-Options              | Header is missing; MIME-type sniffing may lead to XSS via content confusion attacks                                                                                                                      | 65    |
| Cache Control Analyzer             | 🟡 MEDIUM | Cache-Control                       | Sensitive response allows caching for 604800s without no-store                                                                                                                                           | 12    |
| Information Leak Analyzer          | 🟡 MEDIUM | Server Header                       | Server header present and may aid fingerprinting: 'Apache'                                                                                                                                               | 2     |
| Security Headers Analyzer          | 🔵 LOW    | Permissions-Policy                  | Header is absent; browser features (camera, geolocation, etc.) are not restricted                                                                                                                        | 70    |
| Security Headers Analyzer          | 🔵 LOW    | Referrer-Policy                     | Header is absent; browser default may leak full URL in Referer header to cross-origin destinations                                                                                                       | 68    |
| Security Rating & Grade Calculator | 🔵 LOW    | Header Conflict: Cookie without CSP | Set-Cookie present but Content-Security-Policy is missing — cookies may be accessible to injected scripts                                                                                                | 68    |
| Cookie & JWT Analyzer              | 🔵 LOW    | Set-Cookie (TS0d265b7a027)          | HttpOnly flag is missing; JavaScript, including any injected via XSS, can read this cookie                                                                                                               | 67    |
| Cookie & JWT Analyzer              | 🔵 LOW    | Set-Cookie (TS0d265b7a027)          | No SameSite attribute; modern browsers default to Lax, but an explicit value is recommended for sensitive cookies                                                                                        | 67    |
| Cache Control Analyzer             | 🔵 LOW    | Cache-Control                       | Response varies by authenticated context but Vary header does not include Authorization/Cookie — risk of shared-cache mixing between users                                                               | 12    |
| Cache Control Analyzer             | 🔵 LOW    | Cache-Control                       | Validator headers (ETag/Last-Modified) present on a sensitive response — conditional requests may keep a cached copy available                                                                           | 12    |
| Security Headers Analyzer          | 🔵 LOW    | X-XSS-Protection                    | Deprecated header '1; mode=block' is present; modern browsers ignore it, and in legacy browsers (IE/old Chrome) it can introduce new XSS vectors. Remove it and rely on Content-Security-Policy instead. | 3     |
| Cookie & JWT Analyzer              | 🔵 LOW    | Set-Cookie (JSESSIONID)             | No SameSite attribute; modern browsers default to Lax, but an explicit value is recommended for sensitive cookies                                                                                        | 1     |
| Information Leak Analyzer          | 🔵 LOW    | Cookie Security                     | Cookie 'JSESSIONID' lacks 'SameSite' attribute — vulnerable to CSRF                                                                                                                                      | 1     |


### Analyzed Entries

| Source            | Method | URL                                                                                                                                        | Status | Grade | Score | Recommendations                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| ----------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------ | ------ | ----- | ----- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| burp_traffic.json | GET    | https://www.azercell.com:443/TSPD/?type=22                                                                                                 | 200    |       |       | []                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| burp_traffic.json | GET    | https://www.azercell.com:443/az/                                                                                                           | 200    |       |       | []                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| burp_traffic.json | GET    | https://www.azercell.com:443/assets/cache/webp/theme/images/kids.png.webp                                                                  | 200    |       |       | []                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| burp_traffic.json | GET    | https://www.azercell.com:443/az/evo-serviceworker                                                                                          | 200    | F     | 32.0  | ["HIGH: Remediate 7 high severity issue(s) as next priority", "No CORS headers — same-origin policy is in effect (acceptable unless cross-origin API access is needed)", "Missing Referrer-Policy — browser default may leak full URL in Referer header", "Missing Content-Security-Policy — implement a policy to mitigate XSS and data injection", "Missing Permissions-Policy — sensitive browser features (camera, geolocation, etc.) are unrestricted", "Missing X-Content-Type-Options — browsers may MIME-sniff leading to content confusion attacks", "Missing X-Frame-Options — page may be vulnerable to clickjacking attacks", "Missing Strict-Transport-Security — configure on HTTPS responses to enforce TLS", "Cache-Control allows public caching of sensitive data — set no-store for authenticated responses", "MEDIUM: Review 1 medium severity finding(s) in next sprint"] |
| burp_traffic.json | GET    | https://www.azercell.com:443/TSPD/08ec0d819fab28005dd0e8f6833e288fcb0266fe45b27dbee2b31d7487818cb74418f2f4af75625800400af6a4eb1931?type=13 | 200    | D     | 50.0  | ["HIGH: Remediate 5 high severity issue(s) as next priority", "No CORS headers — same-origin policy is in effect (acceptable unless cross-origin API access is needed)", "Missing Referrer-Policy — browser default may leak full URL in Referer header", "Missing Content-Security-Policy — implement a policy to mitigate XSS and data injection", "Missing Permissions-Policy — sensitive browser features (camera, geolocation, etc.) are unrestricted", "Missing Strict-Transport-Security — configure on HTTPS responses to enforce TLS"]                                                                                                                                                                                                                                                                                                                                                |
| burp_traffic.json | GET    | https://careers.digitalecosystem.az:443/Azercell                                                                                           | 200    | C     | 71.0  | ["HIGH: Remediate 3 high severity issue(s) as next priority", "Missing Content-Security-Policy — implement a policy to mitigate XSS and data injection", "No CORS headers — same-origin policy is in effect (acceptable unless cross-origin API access is needed)", "Missing Permissions-Policy — sensitive browser features (camera, geolocation, etc.) are unrestricted"]                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |


### WebSocket

- **Handshakes:** 0 | Accepted: 0 | Rejected: 0

- **Notes:** ["Only handshakes can be analyzed from HTTP history exports; WebSocket frame contents are not part of the intercept file"]


### Cookies

| Name          | Host                        | Sensitive | Secure | HttpOnly | SameSite | JWT | Category       | Lifetime (s) | Issued | Sent |
| ------------- | --------------------------- | --------- | ------ | -------- | -------- | --- | -------------- | ------------ | ------ | ---- |
| JSESSIONID    | careers.digitalecosystem.az | ⚠️ Yes    | ✅      | ✅        | Not Set  | No  | session        |              | 1      | 1    |
| TS00000000074 | www.azercell.com            | No        | ❌      | ❌        | Not Set  | No  | load_balancer  |              | 0      | 1    |
| TS00000000076 | www.azercell.com            | No        | ❌      | ❌        | Not Set  | No  | load_balancer  |              | 0      | 67   |
| TS01cf4ea3    | www.azercell.com            | No        | ❌      | ❌        | Not Set  | No  | load_balancer  |              | 0      | 68   |
| TS0d265b7a027 | www.azercell.com            | No        | ❌      | ❌        | Not Set  | No  | load_balancer  |              | 67     | 68   |
| TS7ab72b08029 | www.azercell.com            | No        | ❌      | ❌        | Not Set  | No  | load_balancer  |              | 0      | 68   |
| TS7ab72b08077 | www.azercell.com            | No        | ❌      | ❌        | Not Set  | No  | load_balancer  |              | 0      | 67   |
| TS7ab72b08078 | www.azercell.com            | No        | ❌      | ❌        | Not Set  | No  | load_balancer  |              | 0      | 66   |
| TSPD_101      | www.azercell.com            | No        | ❌      | ❌        | Not Set  | No  | bot_protection |              | 0      | 68   |
| TSPD_101_DID  | www.azercell.com            | No        | ❌      | ❌        | Not Set  | No  | bot_protection |              | 0      | 65   |
| _snp_id.4cf5  | www.azercell.com            | No        | ❌      | ❌        | Not Set  | No  |                |              | 0      | 68   |
| closed-bar    | www.azercell.com            | No        | ❌      | ❌        | Not Set  | No  |                |              | 0      | 68   |
| evo1xcukdl    | www.azercell.com            | No        | ❌      | ❌        | Not Set  | No  |                |              | 0      | 68   |
| sp            | www.azercell.com            | No        | ❌      | ❌        | Not Set  | No  |                |              | 0      | 68   |


### Cookie Findings

| Cookie        | Host                        | Severity | Header                     | Detail                                                                                                                    | Count |
| ------------- | --------------------------- | -------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ----- |
| TS0d265b7a027 | www.azercell.com            | 🟡 MEDIUM | Set-Cookie (TS0d265b7a027) | Secure flag is missing on a cookie set over HTTPS; it can be sent over a future plaintext HTTP connection and intercepted | 67    |
| JSESSIONID    | careers.digitalecosystem.az | 🔵 LOW    | Set-Cookie (JSESSIONID)    | No SameSite attribute; modern browsers default to Lax, but an explicit value is recommended for sensitive cookies         | 1     |
| TS0d265b7a027 | www.azercell.com            | 🔵 LOW    | Set-Cookie (TS0d265b7a027) | HttpOnly flag is missing; JavaScript, including any injected via XSS, can read this cookie                                | 67    |
| TS0d265b7a027 | www.azercell.com            | 🔵 LOW    | Set-Cookie (TS0d265b7a027) | No SameSite attribute; modern browsers default to Lax, but an explicit value is recommended for sensitive cookies         | 67    |


### Detailed Header Findings

| Entry | Module                             | Severity | Header                              | Detail                                                                                                                                                                                                   |
| ----- | ---------------------------------- | -------- | ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1     | Security Headers Analyzer          | 🟠 HIGH   | Strict-Transport-Security           | Header is missing                                                                                                                                                                                        |
| 1     | Security Headers Analyzer          | 🟠 HIGH   | Content-Security-Policy             | Header is missing                                                                                                                                                                                        |
| 10    | Cache Control Analyzer             | 🟠 HIGH   | Cache-Control                       | public directive on a sensitive response — shared caches and proxies may store this content                                                                                                              |
| 3     | Security Headers Analyzer          | 🟠 HIGH   | X-Frame-Options                     | Header is missing; page may be vulnerable to clickjacking                                                                                                                                                |
| 10    | Cache Control Analyzer             | 🟡 MEDIUM | Cache-Control                       | Sensitive response allows caching for 604800s without no-store                                                                                                                                           |
| 2     | Cookie & JWT Analyzer              | 🟡 MEDIUM | Set-Cookie (TS0d265b7a027)          | Secure flag is missing on a cookie set over HTTPS; it can be sent over a future plaintext HTTP connection and intercepted                                                                                |
| 3     | Security Headers Analyzer          | 🟡 MEDIUM | X-Content-Type-Options              | Header is missing; MIME-type sniffing may lead to XSS via content confusion attacks                                                                                                                      |
| 67    | Information Leak Analyzer          | 🟡 MEDIUM | Server Header                       | Server header present and may aid fingerprinting: 'Apache'                                                                                                                                               |
| 1     | Security Headers Analyzer          | 🔵 LOW    | Referrer-Policy                     | Header is absent; browser default may leak full URL in Referer header to cross-origin destinations                                                                                                       |
| 1     | Security Headers Analyzer          | 🔵 LOW    | Permissions-Policy                  | Header is absent; browser features (camera, geolocation, etc.) are not restricted                                                                                                                        |
| 1     | Security Headers Analyzer          | 🔵 LOW    | X-XSS-Protection                    | Deprecated header '1; mode=block' is present; modern browsers ignore it, and in legacy browsers (IE/old Chrome) it can introduce new XSS vectors. Remove it and rely on Content-Security-Policy instead. |
| 10    | Cache Control Analyzer             | 🔵 LOW    | Cache-Control                       | Validator headers (ETag/Last-Modified) present on a sensitive response — conditional requests may keep a cached copy available                                                                           |
| 2     | Security Rating & Grade Calculator | 🔵 LOW    | Header Conflict: Cookie without CSP | Set-Cookie present but Content-Security-Policy is missing — cookies may be accessible to injected scripts                                                                                                |
| 2     | Cookie & JWT Analyzer              | 🔵 LOW    | Set-Cookie (TS0d265b7a027)          | HttpOnly flag is missing; JavaScript, including any injected via XSS, can read this cookie                                                                                                               |
| 2     | Cookie & JWT Analyzer              | 🔵 LOW    | Set-Cookie (TS0d265b7a027)          | No SameSite attribute; modern browsers default to Lax, but an explicit value is recommended for sensitive cookies                                                                                        |
| 4     | Cache Control Analyzer             | 🔵 LOW    | Cache-Control                       | Response varies by authenticated context but Vary header does not include Authorization/Cookie — risk of shared-cache mixing between users                                                               |
| 67    | Information Leak Analyzer          | 🔵 LOW    | Cookie Security                     | Cookie 'JSESSIONID' lacks 'SameSite' attribute — vulnerable to CSRF                                                                                                                                      |
| 67    | Cookie & JWT Analyzer              | 🔵 LOW    | Set-Cookie (JSESSIONID)             | No SameSite attribute; modern browsers default to Lax, but an explicit value is recommended for sensitive cookies                                                                                        |


### Headers Result Payload

```json
{
  "domain": "azercell.com",
  "intercept_files": [
    "C:\\Users\\senag\\Desktop\\Oxsium-Web-Framework\\Main\\Scan-Results\\burp_traffic.json"
  ],
  "timestamp": "2026-10-08T10:44:30.803234Z",
  "elapsed_ms": 508.96,
  "records_read": 70,
  "responses_analyzed": 70,
  "entries": [
    {
      "id": "1",
      "source": "burp_traffic.json",
      "method": "GET",
      "url": "https://www.azercell.com:443/TSPD/08ec0d819fab28005dd0e8f6833e288fcb0266fe45b27dbee2b31d7487818cb74418f2f4af75625800400af6a4eb1931?type=13",
      "status_code": 200,
      "modules": {
        "Security Headers Analyzer": {
          "module": "Security Headers Analyzer",
          "findings": [
            {
              "severity": "HIGH",
              "header": "Strict-Transport-Security",
              "detail": "Header is missing"
            },
            {
              "severity": "HIGH",
              "header": "Content-Security-Policy",
              "detail": "Header is missing"
            },
            {
              "severity": "LOW",
              "header": "Referrer-Policy",
              "detail": "Header is absent; browser default may leak full URL in Referer header to cross-origin destinations"
            },
            {
              "severity": "LOW",
              "header": "Permissions-Policy",
              "detail": "Header is absent; browser features (camera, geolocation, etc.) are not restricted"
            },
            {
              "severity": "LOW",
              "header": "X-XSS-Protection",
              "detail": "Deprecated header '1; mode=block' is present; modern browsers ignore it, and in legacy browsers (IE/old Chrome) it can introduce new XSS vectors. Remove it and rely on Content-Security-Policy instead."
            }
          ],
          "error": null
        }
      },
      "score": {
        "grade": "D",
        "score": 50.0,
        "recommendations": [
          "HIGH: Remediate 5 high severity issue(s) as next priority",
          "No CORS headers — same-origin policy is in effect (acceptable unless cross-origin API access is needed)",
          "Missing Referrer-Policy — browser default may leak full URL in Referer header",
          "Missing Content-Security-Policy — implement a policy to mitigate XSS and data injection",
          "Missing Permissions-Policy — sensitive browser features (camera, geolocation, etc.) are unrestricted",
          "Missing Strict-Transport-Security — configure on HTTPS responses to enforce TLS"
        ]
      }
    },
    {
      "id": "2",
      "source": "burp_traffic.json",
      "method": "GET",
      "url": "https://www.azercell.com:443/TSPD/?type=22",
      "status_code": 200,
      "modules": {
        "Security Rating & Grade Calculator": {
          "module": "Security Rating & Grade Calculator",
          "findings": [
            {
              "severity": "LOW",
              "header": "Header Conflict: Cookie without CSP",
              "detail": "Set-Cookie present but Content-Security-Policy is missing — cookies may be accessible to injected scripts"
            }
          ],
          "error": null
        },
        "Cookie & JWT Analyzer": {
          "module": "Cookie & JWT Analyzer",
          "findings": [
            {
              "severity": "MEDIUM",
              "header": "Set-Cookie (TS0d265b7a027)",
              "detail": "Secure flag is missing on a cookie set over HTTPS; it can be sent over a future plaintext HTTP connection and intercepted"
            },
            {
              "severity": "LOW",
              "header": "Set-Cookie (TS0d265b7a027)",
              "detail": "HttpOnly flag is missing; JavaScript, including any injected via XSS, can read this cookie"
            },
            {
              "severity": "LOW",
              "header": "Set-Cookie (TS0d265b7a027)",
              "detail": "No SameSite attribute; modern browsers default to Lax, but an explicit value is recommended for sensitive cookies"
            }
          ],
          "error": null
        }
      },
      "score": null
    },
    {
      "id": "3",
      "source": "burp_traffic.json",
      "method": "GET",
      "url": "https://www.azercell.com:443/az/evo-serviceworker",
      "status_code": 200,
      "modules": {
        "Security Headers Analyzer": {
          "module": "Security Headers Analyzer",
          "findings": [
            {
              "severity": "HIGH",
              "header": "X-Frame-Options",
              "detail": "Header is missing; page may be vulnerable to clickjacking"
            },
            {
              "severity": "MEDIUM",
              "header": "X-Content-Type-Options",
              "detail": "Header is missing; MIME-type sniffing may lead to XSS via content confusion attacks"
            }
          ],
          "error": null
        }
      },
      "score": {
        "grade": "F",
        "score": 32.0,
        "recommendations": [
          "HIGH: Remediate 7 high severity issue(s) as next priority",
          "No CORS headers — same-origin policy is in effect (acceptable unless cross-origin API access is needed)",
          "Missing Referrer-Policy — browser default may leak full URL in Referer header",
          "Missing Content-Security-Policy — implement a policy to mitigate XSS and data injection",
          "Missing Permissions-Policy — sensitive browser features (camera, geolocation, etc.) are unrestricted",
          "Missing X-Content-Type-Options — browsers may MIME-sniff leading to content confusion attacks",
          "Missing X-Frame-Options — page may be vulnerable to clickjacking attacks",
          "Missing Strict-Transport-Security — configure on HTTPS responses to enforce TLS",
          "Cache-Control allows public caching of sensitive data — set no-store for authenticated responses",
          "MEDIUM: Review 1 medium severity finding(s) in next sprint"
        ]
      }
    },
    {
      "id": "4",
      "source": "burp_traffic.json",
      "method": "GET",
      "url": "https://www.azercell.com:443/az/",
      "status_code": 200,
      "modules": {
        "Cache Control Analyzer": {
          "module": "Cache Control Analyzer",
          "findings": [
            {
              "severity": "LOW",
              "header": "Cache-Control",
              "detail": "Response varies by authenticated context but Vary header does not include Authorization/Cookie — risk of shared-cache mixing between users"
            }
          ],
          "error": null
        }
      },
      "score": null
    },
    {
      "id": "10",
      "source": "burp_traffic.json",
      "method": "GET",
      "url": "https://www.azercell.com:443/assets/cache/webp/theme/images/kids.png.webp",
      "status_code": 200,
      "modules": {
        "Cache Control Analyzer": {
          "module": "Cache Control Analyzer",
          "findings": [
            {
              "severity": "HIGH",
              "header": "Cache-Control",
              "detail": "public directive on a sensitive response — shared caches and proxies may store this content"
            },
            {
              "severity": "MEDIUM",
              "header": "Cache-Control",
              "detail": "Sensitive response allows caching for 604800s without no-store"
            },
            {
              "severity": "LOW",
              "header": "Cache-Control",
              "detail": "Validator headers (ETag/Last-Modified) present on a sensitive response — conditional requests may keep a cached copy available"
            }
          ],
          "error": null
        }
      },
      "score": null
    },
    {
      "id": "67",
      "source": "burp_traffic.json",
      "method": "GET",
      "url": "https://careers.digitalecosystem.az:443/Azercell",
      "status_code": 200,
      "modules": {
        "Information Leak Analyzer": {
          "module": "Information Leak Analyzer",
          "findings": [
            {
              "severity": "MEDIUM",
              "header": "Server Header",
              "detail": "Server header present and may aid fingerprinting: 'Apache'"
            },
            {
              "severity": "LOW",
              "header": "Cookie Security",
              "detail": "Cookie 'JSESSIONID' lacks 'SameSite' attribute — vulnerable to CSRF"
            }
          ],
          "error": null
        },
        "Cookie & JWT Analyzer": {
          "module": "Cookie & JWT Analyzer",
          "findings": [
            {
              "severity": "LOW",
              "header": "Set-Cookie (JSESSIONID)",
              "detail": "No SameSite attribute; modern browsers default to Lax, but an explicit value is recommended for sensitive cookies"
            }
          ],
          "error": null
        }
      },
      "score": {
        "grade": "C",
        "score": 71.0,
        "recommendations": [
          "HIGH: Remediate 3 high severity issue(s) as next priority",
          "Missing Content-Security-Policy — implement a policy to mitigate XSS and data injection",
          "No CORS headers — same-origin policy is in effect (acceptable unless cross-origin API access is needed)",
          "Missing Permissions-Policy — sensitive browser features (camera, geolocation, etc.) are unrestricted"
        ]
      }
    }
  ],
  "summary": [
    {
      "module": "Security Headers Analyzer",
      "severity": "HIGH",
      "header": "Content-Security-Policy",
      "detail": "Header is missing",
      "count": 70,
      "entry_ids": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ],
      "entries_total": 70
    },
    {
      "module": "Security Headers Analyzer",
      "severity": "HIGH",
      "header": "Strict-Transport-Security",
      "detail": "Header is missing",
      "count": 68,
      "entry_ids": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ],
      "entries_total": 68
    },
    {
      "module": "Security Headers Analyzer",
      "severity": "HIGH",
      "header": "X-Frame-Options",
      "detail": "Header is missing; page may be vulnerable to clickjacking",
      "count": 65,
      "entry_ids": [
        "3",
        "4",
        "5",
        "6",
        "7"
      ],
      "entries_total": 65
    },
    {
      "module": "Cache Control Analyzer",
      "severity": "HIGH",
      "header": "Cache-Control",
      "detail": "public directive on a sensitive response — shared caches and proxies may store this content",
      "count": 12,
      "entry_ids": [
        "10",
        "14",
        "25",
        "20",
        "24"
      ],
      "entries_total": 12
    },
    {
      "module": "Cookie & JWT Analyzer",
      "severity": "MEDIUM",
      "header": "Set-Cookie (TS0d265b7a027)",
      "detail": "Secure flag is missing on a cookie set over HTTPS; it can be sent over a future plaintext HTTP connection and intercepted",
      "count": 67,
      "entry_ids": [
        "2",
        "3",
        "4",
        "5",
        "6"
      ],
      "entries_total": 67
    },
    {
      "module": "Security Headers Analyzer",
      "severity": "MEDIUM",
      "header": "X-Content-Type-Options",
      "detail": "Header is missing; MIME-type sniffing may lead to XSS via content confusion attacks",
      "count": 65,
      "entry_ids": [
        "3",
        "4",
        "5",
        "6",
        "7"
      ],
      "entries_total": 65
    },
    {
      "module": "Cache Control Analyzer",
      "severity": "MEDIUM",
      "header": "Cache-Control",
      "detail": "Sensitive response allows caching for 604800s without no-store",
      "count": 12,
      "entry_ids": [
        "10",
        "14",
        "25",
        "20",
        "24"
      ],
      "entries_total": 12
    },
    {
      "module": "Information Leak Analyzer",
      "severity": "MEDIUM",
      "header": "Server Header",
      "detail": "Server header present and may aid fingerprinting: 'Apache'",
      "count": 2,
      "entry_ids": [
        "67",
        "68"
      ],
      "entries_total": 2
    },
    {
      "module": "Security Headers Analyzer",
      "severity": "LOW",
      "header": "Permissions-Policy",
      "detail": "Header is absent; browser features (camera, geolocation, etc.) are not restricted",
      "count": 70,
      "entry_ids": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ],
      "entries_total": 70
    },
    {
      "module": "Security Headers Analyzer",
      "severity": "LOW",
      "header": "Referrer-Policy",
      "detail": "Header is absent; browser default may leak full URL in Referer header to cross-origin destinations",
      "count": 68,
      "entry_ids": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ],
      "entries_total": 68
    },
    {
      "module": "Security Rating & Grade Calculator",
      "severity": "LOW",
      "header": "Header Conflict: Cookie without CSP",
      "detail": "Set-Cookie present but Content-Security-Policy is missing — cookies may be accessible to injected scripts",
      "count": 68,
      "entry_ids": [
        "2",
        "3",
        "4",
        "5",
        "6"
      ],
      "entries_total": 68
    },
    {
      "module": "Cookie & JWT Analyzer",
      "severity": "LOW",
      "header": "Set-Cookie (TS0d265b7a027)",
      "detail": "HttpOnly flag is missing; JavaScript, including any injected via XSS, can read this cookie",
      "count": 67,
      "entry_ids": [
        "2",
        "3",
        "4",
        "5",
        "6"
      ],
      "entries_total": 67
    },
    {
      "module": "Cookie & JWT Analyzer",
      "severity": "LOW",
      "header": "Set-Cookie (TS0d265b7a027)",
      "detail": "No SameSite attribute; modern browsers default to Lax, but an explicit value is recommended for sensitive cookies",
      "count": 67,
      "entry_ids": [
        "2",
        "3",
        "4",
        "5",
        "6"
      ],
      "entries_total": 67
    },
    {
      "module": "Cache Control Analyzer",
      "severity": "LOW",
      "header": "Cache-Control",
      "detail": "Response varies by authenticated context but Vary header does not include Authorization/Cookie — risk of shared-cache mixing between users",
      "count": 12,
      "entry_ids": [
        "4",
        "16",
        "25",
        "20",
        "24"
      ],
      "entries_total": 12
    },
    {
      "module": "Cache Control Analyzer",
      "severity": "LOW",
      "header": "Cache-Control",
      "detail": "Validator headers (ETag/Last-Modified) present on a sensitive response — conditional requests may keep a cached copy available",
      "count": 12,
      "entry_ids": [
        "10",
        "14",
        "25",
        "20",
        "24"
      ],
      "entries_total": 12
    },
    {
      "module": "Security Headers Analyzer",
      "severity": "LOW",
      "header": "X-XSS-Protection",
      "detail": "Deprecated header '1; mode=block' is present; modern browsers ignore it, and in legacy browsers (IE/old Chrome) it can introduce new XSS vectors. Remove it and rely on Content-Security-Policy instead.",
      "count": 3,
      "entry_ids": [
        "1",
        "2",
        "69"
      ],
      "entries_total": 3
    },
    {
      "module": "Cookie & JWT Analyzer",
      "severity": "LOW",
      "header": "Set-Cookie (JSESSIONID)",
      "detail": "No SameSite attribute; modern browsers default to Lax, but an explicit value is recommended for sensitive cookies",
      "count": 1,
      "entry_ids": [
        "67"
      ],
      "entries_total": 1
    },
    {
      "module": "Information Leak Analyzer",
      "severity": "LOW",
      "header": "Cookie Security",
      "detail": "Cookie 'JSESSIONID' lacks 'SameSite' attribute — vulnerable to CSRF",
      "count": 1,
      "entry_ids": [
        "67"
      ],
      "entries_total": 1
    }
  ],
  "websocket": {
    "totals": {
      "handshakes": 0,
      "accepted": 0,
      "rejected": 0,
      "other_upgrades": 0
    },
    "endpoints": [],
    "notes": [
      "Only handshakes can be analyzed from HTTP history exports; WebSocket frame contents are not part of the intercept file"
    ]
  },
  "cookie_report": {
    "cookies": [
      {
        "name": "JSESSIONID",
        "host": "careers.digitalecosystem.az",
        "fingerprint": "Java servlet container session (Tomcat, Jetty, WebLogic, WebSphere and others)",
        "category": "session",
        "sensitive": true,
        "value_type": "opaque",
        "layers": [],
        "decoded": null,
        "entropy": {
          "length": 35,
          "charset": "mixed",
          "shannon_bits_per_char": 3.843,
          "uniformity": 0.585,
          "estimated_bits": 134.5,
          "patterns": []
        },
        "hash_candidates": [],
        "provider_tokens": [],
        "issued_in": [
          "67"
        ],
        "sent_in": [
          "68"
        ],
        "values": [
          {
            "value": "w1~A3BF9F5B6FECE45784784E21E7A29989",
            "count": 2
          }
        ],
        "attribute_sets": [
          {
            "secure": true,
            "httponly": true,
            "samesite": null,
            "partitioned": false,
            "domain": null,
            "path": "/",
            "max_age": null,
            "expires": null,
            "lifetime_seconds": null
          }
        ],
        "findings": [
          {
            "severity": "LOW",
            "header": "Set-Cookie (JSESSIONID)",
            "detail": "No SameSite attribute; modern browsers default to Lax, but an explicit value is recommended for sensitive cookies",
            "count": 1
          }
        ],
        "distinct_values": 1,
        "issued_total": 1,
        "sent_total": 1
      },
      {
        "name": "TS00000000074",
        "host": "www.azercell.com",
        "fingerprint": "F5 BIG-IP ASM / Advanced WAF TS cookie",
        "category": "load_balancer",
        "sensitive": false,
        "value_type": "opaque-token",
        "layers": [],
        "decoded": null,
        "entropy": {
          "length": 1056,
          "charset": "hex-lower",
          "shannon_bits_per_char": 3.991,
          "uniformity": 0.998,
          "estimated_bits": 4214.5,
          "patterns": []
        },
        "hash_candidates": [],
        "provider_tokens": [],
        "issued_in": [],
        "sent_in": [
          "1"
        ],
        "values": [
          {
            "value": "08ec0d819fab28005dd0e8f6833e288fcb0266fe45b27dbee2b31d7487818cb74418f2f4af75625800400af6a4eb193108324e1ccf07d801b2000f6b23ebd3d702538058ad1515dd1c2c006efc93f82b170b5346b4afde186e8ff638650be4afb9a2714d654497a1df5a08e41f4d291add2c36ad44b6fac42657e8763c462113061a8f25e05554e4c61f73d7aaa9021fb10d12c401dcaca08877f2c28938d297c268d05f3aa40ee171b2a30e0755742009108bf23b86e60e92e080071d41e148076e86f334ba490037241e7bf0fc14e495a5bfe4cff60a1e9fa4bb6e191fc268ae9a4b8953c03aa3f7b3293997b9d2f35c75f850fa1e48e73401769b7d55106c0b9b3c3391cdfcb2c4056a5d778aa36dbd542b725a9bed8438d0381446e42e452a7910d2aa70d9c02987f54ade5aad0a5b96ac98add4847db2216477094c24adb3bd5b9e830d3eea6d96d4dd70e71ca26a0f9abcc45a80733899ac7e8214a1c005ef86d841eaf1c41156156eca85ab6a56cd375c2bc62bb6eb5256ad4c3491aac327c4e594865236610d81370a805658ef9561192e8736593ec699c444a78d5624e3297035b34e679d29a7d5967e255fd04e22f307df5e5be1f55ee74ddedf6e5f88334d75dfd93c060b0a394b3eeaf94d8742c50dd0c08ee6011d3159bdd2112d8d174453fb721b50131a93556fdcb343c1756bb189c748f5c86d87af5cf7720aaabf6e606704b0fbbda3bf359ad412",
            "count": 1
          }
        ],
        "attribute_sets": [],
        "findings": [],
        "distinct_values": 1,
        "issued_total": 0,
        "sent_total": 1
      },
      {
        "name": "TS00000000076",
        "host": "www.azercell.com",
        "fingerprint": "F5 BIG-IP ASM / Advanced WAF TS cookie",
        "category": "load_balancer",
        "sensitive": false,
        "value_type": "opaque-token",
        "layers": [],
        "decoded": null,
        "entropy": {
          "length": 528,
          "charset": "hex-lower",
          "shannon_bits_per_char": 3.969,
          "uniformity": 0.992,
          "estimated_bits": 2095.6,
          "patterns": []
        },
        "hash_candidates": [],
        "provider_tokens": [],
        "issued_in": [],
        "sent_in": [
          "2",
          "3",
          "4",
          "5",
          "6",
          "7",
          "8",
          "11",
          "12",
          "10",
          "9",
          "13",
          "15",
          "14",
          "16"
        ],
        "values": [
          {
            "value": "08ec0d819fab28005dd0e8f6833e288fcb0266fe45b27dbee2b31d7487818cb74418f2f4af75625800400af6a4eb193108324e1ccf09d0001fe208151e4913a3cefcaa58e228b2d7422de678358ae93820c3320bc5b8dca504d98ccdefba03d33f489204db11d98718432c1b76fc4f52035c40d95278c7c937b3478d9207f1a0989d45c3d3f277da430a3c6c37bde054b3396f29131c2c698d6d2a7673a088a6d6553583cf61f3b79353d26735c40579f865a1605924f5feeb0abb2d9f3c6b4dfc37da973ef832c7024151c17803871f77d8fa57ece2f131dc9819dbca14408e01ed59ce33c02d28a6f0c90beb8039bbd294e397e1c55a13d93287c5d414ce5d55018b9a30009c3e",
            "count": 67
          }
        ],
        "attribute_sets": [],
        "findings": [],
        "distinct_values": 1,
        "issued_total": 0,
        "sent_total": 67
      },
      {
        "name": "TS01cf4ea3",
        "host": "www.azercell.com",
        "fingerprint": "F5 BIG-IP ASM / Advanced WAF TS cookie",
        "category": "load_balancer",
        "sensitive": false,
        "value_type": "opaque-token",
        "layers": [],
        "decoded": null,
        "entropy": {
          "length": 138,
          "charset": "hex-lower",
          "shannon_bits_per_char": 3.939,
          "uniformity": 0.985,
          "estimated_bits": 543.6,
          "patterns": []
        },
        "hash_candidates": [],
        "provider_tokens": [],
        "issued_in": [],
        "sent_in": [
          "1",
          "2",
          "3",
          "4",
          "5",
          "6",
          "7",
          "8",
          "11",
          "12",
          "10",
          "9",
          "13",
          "15",
          "14"
        ],
        "values": [
          {
            "value": "01db3e592eecca1857cb04739ab02d184abbb659e207c24d01d176aa98e8537c055257b9eb16c47fad5d23c92da56d3f390ff2202c44fe9ca7bcbb4f3ccd475946d2002237",
            "count": 68
          }
        ],
        "attribute_sets": [],
        "findings": [],
        "distinct_values": 1,
        "issued_total": 0,
        "sent_total": 68
      },
      {
        "name": "TS0d265b7a027",
        "host": "www.azercell.com",
        "fingerprint": "F5 BIG-IP ASM / Advanced WAF TS cookie",
        "category": "load_balancer",
        "sensitive": false,
        "value_type": "opaque-token",
        "layers": [],
        "decoded": null,
        "entropy": {
          "length": 192,
          "charset": "hex-lower",
          "shannon_bits_per_char": 3.919,
          "uniformity": 0.98,
          "estimated_bits": 752.5,
          "patterns": []
        },
        "hash_candidates": [],
        "provider_tokens": [],
        "issued_in": [
          "2",
          "3",
          "4",
          "5",
          "6",
          "7",
          "8",
          "11",
          "12",
          "10",
          "9",
          "13",
          "15",
          "14",
          "16"
        ],
        "sent_in": [
          "1",
          "2",
          "3",
          "4",
          "5",
          "6",
          "7",
          "8",
          "11",
          "12",
          "10",
          "9",
          "13",
          "15",
          "14"
        ],
        "values": [
          {
            "value": "08ec0d819fab20009e9320d893b5949d52ccef00d311f657127be235e86d3c9e1c8c09cd26a533ae081d0c4e661130005701684c5ce886bb49d95cf8d72fbe97e162b5d33d938376c2695df9b15599d95b126270015d0893b60b1731404091c9",
            "count": 2
          },
          {
            "value": "08ec0d819fab20008565b9bf03da601974167c87a0a81e405927d9c3112bfea647bde0e1fb3bdcd808428c17d21130003339b73e046ca47bc7b8df6007a81128cc604d2fa1ef0532813e32072637aa08777ea6ebf97384c1a64c6a8de9d61710",
            "count": 2
          },
          {
            "value": "08ec0d819fab200053fa1f2b379423a1ab6f27e7f9b2a845abcf867aec2bb924d9c4f4dd51ec273808989054cd113000f4e378a469de27595713eb7238aaf54e7a2e701f5804264946474c45a3558dcd5517bd638b2b0a25ba6b6904baf92b2b",
            "count": 2
          },
          {
            "value": "08ec0d819fab2000882b235cfe260a798429f8424a91fcad5d091a9a040a5d38445cf1ed9be13203083de904ab113000b4e84ee89f3674615713eb7238aaf54e7a2e701f5804264946474c45a3558dcd5517bd638b2b0a25ba6b6904baf92b2b",
            "count": 2
          },
          {
            "value": "08ec0d819fab20001dd5de22aefd69af0482c20a66cb7bd2cdec602f0decc9a5e90541bea77f6c1108341f38d8113000f60357b9a7ab7499e411e86fe5e644e9a8bba3caafb60c7056d0bfa6071b7f00f345ca99bc67eef81b1ba80244fc41f1",
            "count": 2
          }
        ],
        "attribute_sets": [
          {
            "secure": false,
            "httponly": false,
            "samesite": null,
            "partitioned": false,
            "domain": null,
            "path": "/",
            "max_age": null,
            "expires": null,
            "lifetime_seconds": null
          }
        ],
        "findings": [
          {
            "severity": "MEDIUM",
            "header": "Set-Cookie (TS0d265b7a027)",
            "detail": "Secure flag is missing on a cookie set over HTTPS; it can be sent over a future plaintext HTTP connection and intercepted",
            "count": 67
          },
          {
            "severity": "LOW",
            "header": "Set-Cookie (TS0d265b7a027)",
            "detail": "HttpOnly flag is missing; JavaScript, including any injected via XSS, can read this cookie",
            "count": 67
          },
          {
            "severity": "LOW",
            "header": "Set-Cookie (TS0d265b7a027)",
            "detail": "No SameSite attribute; modern browsers default to Lax, but an explicit value is recommended for sensitive cookies",
            "count": 67
          }
        ],
        "distinct_values": 68,
        "issued_total": 67,
        "sent_total": 68
      },
      {
        "name": "TS7ab72b08029",
        "host": "www.azercell.com",
        "fingerprint": "F5 BIG-IP ASM / Advanced WAF TS cookie",
        "category": "load_balancer",
        "sensitive": false,
        "value_type": "hex-token",
        "layers": [],
        "decoded": null,
        "entropy": {
          "length": 96,
          "charset": "hex-lower",
          "shannon_bits_per_char": 3.849,
          "uniformity": 0.962,
          "estimated_bits": 369.5,
          "patterns": []
        },
        "hash_candidates": [
          "SHA-384",
          "SHA3-384"
        ],
        "provider_tokens": [],
        "issued_in": [],
        "sent_in": [
          "1",
          "2",
          "3",
          "4",
          "5",
          "6",
          "7",
          "8",
          "11",
          "12",
          "10",
          "9",
          "13",
          "15",
          "14"
        ],
        "values": [
          {
            "value": "08ec0d819fab2800b787859943612522fbc79e074ee9071ce949fb2bad3c3824c8a8f6ebccc8be3c66830f284eaff35f",
            "count": 3
          },
          {
            "value": "08ec0d819fab28002482cf2d1fac5f777256c6e23272b778871d3eb37fa3181be8fde911cfd99c25f061143939ac3192",
            "count": 1
          },
          {
            "value": "08ec0d819fab2800a3aea334a49d0f1e922252d0f323ba1cc8bedbf7c84e80c7cbf657ea3907673ab6d8a60828c2d16a",
            "count": 2
          },
          {
            "value": "08ec0d819fab2800fdf9cd8fe27cc4e8c17c05d7cbb75e3b062540f2779d2e0f51752f30bfdf458e602721ded92492dd",
            "count": 10
          },
          {
            "value": "08ec0d819fab2800bb74074f035b2500cd4c5548ea7c3a4cc09e882be78587cedf1d8a761400e751e02288db16ac7c4d",
            "count": 18
          }
        ],
        "attribute_sets": [],
        "findings": [],
        "distinct_values": 10,
        "issued_total": 0,
        "sent_total": 68
      },
      {
        "name": "TS7ab72b08077",
        "host": "www.azercell.com",
        "fingerprint": "F5 BIG-IP ASM / Advanced WAF TS cookie",
        "category": "load_balancer",
        "sensitive": false,
        "value_type": "opaque-token",
        "layers": [],
        "decoded": null,
        "entropy": {
          "length": 176,
          "charset": "hex-lower",
          "shannon_bits_per_char": 3.94,
          "uniformity": 0.985,
          "estimated_bits": 693.4,
          "patterns": []
        },
        "hash_candidates": [],
        "provider_tokens": [],
        "issued_in": [],
        "sent_in": [
          "2",
          "3",
          "4",
          "5",
          "6",
          "7",
          "8",
          "11",
          "12",
          "10",
          "9",
          "13",
          "15",
          "14",
          "16"
        ],
        "values": [
          {
            "value": "08ec0d819fab28008036b4c47869f6e462d0f19911992cb8cee8e818bdad5fece6150072bfebddcd737938d6d80f29760817ecc7b3172000cf5394670faee9d5020b3cf022195e15c7f38ae5982d252341d13f407c155172",
            "count": 3
          },
          {
            "value": "08ec0d819fab280055209419f8c12414066dacc39138dd566016913cfdd8f5a5709f66029fb0648a0c3976a5912cbebd08ee1ef7531720008036e1135c4cbda1020b3cf022195e1599ad42835e39b63de0e3704422261081",
            "count": 2
          },
          {
            "value": "08ec0d819fab280055209419f8c12414066dacc39138dd566016913cfdd8f5a5709f66029fb0648a0c3976a5912cbebd08ee1ef75317200055036395bcde5f38020b3cf022195e1555526d425ee1d5010e81996871a11e3a",
            "count": 10
          },
          {
            "value": "08ec0d819fab280055209419f8c12414066dacc39138dd566016913cfdd8f5a5709f66029fb0648a0c3976a5912cbebd08ee1ef753172000d732cf043c6c7e03020b3cf022195e153e824f4ce59733015888740bcc4d07f8",
            "count": 17
          },
          {
            "value": "08ec0d819fab280001c799cfdba4920c2ad8c386b2deb5220223af6a881a0486b40836c9da1180842afb0a6e528da0170845d360731720005654e0d5bc78d5b1020b3cf022195e15e8091ce955a7a7068bf2a05d0af620d9",
            "count": 1
          }
        ],
        "attribute_sets": [],
        "findings": [],
        "distinct_values": 12,
        "issued_total": 0,
        "sent_total": 67
      },
      {
        "name": "TS7ab72b08078",
        "host": "www.azercell.com",
        "fingerprint": "F5 BIG-IP ASM / Advanced WAF TS cookie",
        "category": "load_balancer",
        "sensitive": false,
        "value_type": "opaque-token",
        "layers": [],
        "decoded": null,
        "entropy": {
          "length": 672,
          "charset": "hex-lower",
          "shannon_bits_per_char": 3.989,
          "uniformity": 0.997,
          "estimated_bits": 2680.3,
          "patterns": []
        },
        "hash_candidates": [],
        "provider_tokens": [],
        "issued_in": [],
        "sent_in": [
          "1",
          "2",
          "3",
          "4",
          "5",
          "6",
          "7",
          "8",
          "11",
          "12",
          "10",
          "9",
          "13",
          "15",
          "14"
        ],
        "values": [
          {
            "value": "08ec0d819fab200053b13d2be29a71ebe3895510ce0755ef2af22b6a1c5ee70e569f17d17eae5827087d01424c182001f6a2992b49b51cebad68c7e513aa0208f682bb32f6def66ac0dadeb03c1bd610f5fcdfa1f95d391b9b104bc28768c89d46880df1304f905ccef37470ad7d4f6441394d400d5f25f4ba4f1b6af410bbbc265527f97d6b78dd7f718bbe4b3faadfcc1594c2702815afca9eed1d38dfee3f7ecfb8c6862ced4a15719a7f17d06467b49840385823759b144a3c6d4fc134c70d9fa9546de39e57f30f1e7737920aa70f857c0de1ee542eda4056655954e03a698b18ba227840a7cc5680460ce1182ac7f4425a4415633251a283fa05ef07b049983d9b6259bc5b8618d2700724ed23c9f5d4559835a0e0743edc1446ebbfdec316e449529e714c819898e9f0576e4543017c67af76a8bf7c6a4d4426072214af07f1f2823ec2cf002636d0d7cda152",
            "count": 66
          }
        ],
        "attribute_sets": [],
        "findings": [],
        "distinct_values": 1,
        "issued_total": 0,
        "sent_total": 66
      },
      {
        "name": "TSPD_101",
        "host": "www.azercell.com",
        "fingerprint": "F5 BIG-IP ASM / Advanced WAF Bot Defense (TSPD) cookie",
        "category": "bot_protection",
        "sensitive": false,
        "value_type": "opaque-token",
        "layers": [],
        "decoded": null,
        "entropy": {
          "length": 160,
          "charset": "hex-lower",
          "shannon_bits_per_char": 3.926,
          "uniformity": 0.982,
          "estimated_bits": 628.2,
          "patterns": []
        },
        "hash_candidates": [],
        "provider_tokens": [],
        "issued_in": [],
        "sent_in": [
          "1",
          "2",
          "3",
          "4",
          "5",
          "6",
          "7",
          "8",
          "11",
          "12",
          "10",
          "9",
          "13",
          "15",
          "14"
        ],
        "values": [
          {
            "value": "08ec0d819fab2800a7edcbdfe3139d42973b784018627eec108ef4b93d78a9b05f7e6d432971f2e9b5b7c8dd294a0bb9086ab2e7b3051800ebf9953f3794b9983ef9c2645a786fb1dac1084c9c01fcb7",
            "count": 68
          }
        ],
        "attribute_sets": [],
        "findings": [],
        "distinct_values": 1,
        "issued_total": 0,
        "sent_total": 68
      },
      {
        "name": "TSPD_101_DID",
        "host": "www.azercell.com",
        "fingerprint": "F5 BIG-IP ASM / Advanced WAF Bot Defense (TSPD) cookie",
        "category": "bot_protection",
        "sensitive": false,
        "value_type": "opaque-token",
        "layers": [],
        "decoded": null,
        "entropy": {
          "length": 224,
          "charset": "hex-lower",
          "shannon_bits_per_char": 3.967,
          "uniformity": 0.992,
          "estimated_bits": 888.7,
          "patterns": []
        },
        "hash_candidates": [],
        "provider_tokens": [],
        "issued_in": [],
        "sent_in": [
          "4",
          "5",
          "6",
          "7",
          "8",
          "11",
          "12",
          "10",
          "9",
          "13",
          "15",
          "14",
          "16",
          "17",
          "18"
        ],
        "values": [
          {
            "value": "08ec0d819fab28005dd0e8f6833e288fcb0266fe45b27dbee2b31d7487818cb74418f2f4af75625800400af6a4eb193108324e1ccf0638007e431df998bcb019b64dc12ca57a31a8faff46a85b6a9df38267632bfd62ca1d7917d60cae5553765431c96686d938f65cd5a0e0362d276a",
            "count": 65
          }
        ],
        "attribute_sets": [],
        "findings": [],
        "distinct_values": 1,
        "issued_total": 0,
        "sent_total": 65
      },
      {
        "name": "_snp_id.4cf5",
        "host": "www.azercell.com",
        "fingerprint": null,
        "category": null,
        "sensitive": false,
        "value_type": "opaque",
        "layers": [],
        "decoded": null,
        "entropy": {
          "length": 198,
          "charset": "mixed",
          "shannon_bits_per_char": 4.053,
          "uniformity": 0.617,
          "estimated_bits": 802.5,
          "patterns": []
        },
        "hash_candidates": [],
        "provider_tokens": [],
        "issued_in": [],
        "sent_in": [
          "1",
          "2",
          "3",
          "4",
          "5",
          "6",
          "7",
          "8",
          "11",
          "12",
          "10",
          "9",
          "13",
          "15",
          "14"
        ],
        "values": [
          {
            "value": "de2a9442-2744-4cc1-84bd-968a74a45606.1790496532.2.1791022672.1790496532.9856f908-84c2-4d78-beec-acfe3447bd75.52901279-fefd-4c9e-9ad0-b0b075ae94c6.72a73ca4-af17-477d-b5b2-243085eb2c3b.1791022672245.1",
            "count": 68
          }
        ],
        "attribute_sets": [],
        "findings": [],
        "distinct_values": 1,
        "issued_total": 0,
        "sent_total": 68
      },
      {
        "name": "closed-bar",
        "host": "www.azercell.com",
        "fingerprint": null,
        "category": null,
        "sensitive": false,
        "value_type": "opaque-token",
        "layers": [],
        "decoded": null,
        "entropy": {
          "length": 7,
          "charset": "base64url",
          "shannon_bits_per_char": 2.522,
          "uniformity": 0.42,
          "estimated_bits": 17.7,
          "patterns": []
        },
        "hash_candidates": [],
        "provider_tokens": [],
        "issued_in": [],
        "sent_in": [
          "1",
          "2",
          "3",
          "4",
          "5",
          "6",
          "7",
          "8",
          "11",
          "12",
          "10",
          "9",
          "13",
          "15",
          "14"
        ],
        "values": [
          {
            "value": "get-app",
            "count": 68
          }
        ],
        "attribute_sets": [],
        "findings": [],
        "distinct_values": 1,
        "issued_total": 0,
        "sent_total": 68
      },
      {
        "name": "evo1xcukdl",
        "host": "www.azercell.com",
        "fingerprint": null,
        "category": null,
        "sensitive": false,
        "value_type": "opaque-token",
        "layers": [],
        "decoded": null,
        "entropy": {
          "length": 26,
          "charset": "alnum-lower",
          "shannon_bits_per_char": 3.95,
          "uniformity": 0.764,
          "estimated_bits": 102.7,
          "patterns": []
        },
        "hash_candidates": [],
        "provider_tokens": [],
        "issued_in": [],
        "sent_in": [
          "1",
          "2",
          "3",
          "4",
          "5",
          "6",
          "7",
          "8",
          "11",
          "12",
          "10",
          "9",
          "13",
          "15",
          "14"
        ],
        "values": [
          {
            "value": "udf6st8cik0ifni7bu9psqu0q9",
            "count": 68
          }
        ],
        "attribute_sets": [],
        "findings": [],
        "distinct_values": 1,
        "issued_total": 0,
        "sent_total": 68
      },
      {
        "name": "sp",
        "host": "www.azercell.com",
        "fingerprint": null,
        "category": null,
        "sensitive": false,
        "value_type": "uuid",
        "layers": [],
        "decoded": null,
        "entropy": {
          "length": 36,
          "charset": "base64url",
          "shannon_bits_per_char": 3.652,
          "uniformity": 0.609,
          "estimated_bits": 131.5,
          "patterns": []
        },
        "hash_candidates": [],
        "provider_tokens": [],
        "issued_in": [],
        "sent_in": [
          "1",
          "2",
          "3",
          "4",
          "5",
          "6",
          "7",
          "8",
          "11",
          "12",
          "10",
          "9",
          "13",
          "15",
          "14"
        ],
        "values": [
          {
            "value": "66a9f071-0b7b-4c9b-b79a-d0a559313f96",
            "count": 68
          }
        ],
        "attribute_sets": [],
        "findings": [],
        "distinct_values": 1,
        "issued_total": 0,
        "sent_total": 68
      }
    ],
    "general_findings": [],
    "category_counts": {
      "session": 1,
      "load_balancer": 7,
      "bot_protection": 2,
      "uncategorized": 4
    }
  }
}
```


---

## Technology Fingerprinting

### WAF Detection

- **WAF Detected:** No ✅

- **Generic WAF Detected:** No


### CMS Detection

- **CMS Detected:** No



### Favicon

- **Found:** Yes

- **URL:** https://azercell.com/favicon.ico

- **MMH3:** `146639434`

- **MD5:** `0a01091bebd78b22b129b570c8d81944`

- **SHA1:** `30d746212396b297f7d1c4d20f299708407d664a`

- **File Format:** ICO

- **Shodan Query:** `http.favicon.hash:146639434`

- **FOFA Query:** `icon_hash="146639434"`



### Detected Technologies
_No technologies detected._


### RetireJS (Vulnerable Libraries)
_No vulnerable libraries detected._


---

## Social & Metadata

### Social Profiles

| Platform            | URL                                                               | Source   | Confidence |
| ------------------- | ----------------------------------------------------------------- | -------- | ---------- |
| Apple App Store     | https://apps.apple.com/us/app/azercell-kabinetim/id1459102065     | app_link | low        |
| Facebook            | https://facebook.com/azercell                                     | anchor   | medium     |
| Google Play         | https://play.google.com/store/apps/details?id=com.azercell.ss.app | app_link | low        |
| Huawei AppGallery   | https://appgallery.huawei.com/#/app/C102064131                    | app_link | low        |
| Instagram           | https://www.instagram.com/azercell/                               | anchor   | medium     |
| OneLink (AppsFlyer) | https://onelink.to/gz28e3                                         | app_link | low        |
| X / Twitter         | https://twitter.com/azercell/                                     | anchor   | medium     |
| YouTube             | https://www.youtube.com/c/AzercellYouTube                         | anchor   | medium     |
| YouTube             | https://youtube.com/c/AzercellYouTube                             | anchor   | medium     |


### Emails Found

| Address                | Source      | Context | Verified |
| ---------------------- | ----------- | ------- | -------- |
| zakiyyash@azercell.com | mailto_href |         | ❌        |


### Public Documents

| URL                                                                                              | Category    | File Type              | Source         |
| ------------------------------------------------------------------------------------------------ | ----------- | ---------------------- | -------------- |
| https://www.azercell.com/theme/images/video/comp.mp4                                             | Audio/Video | mp4 video              | request_url    |
| https://www.azercell.com/az/evo-manifest.json                                                    | Data        | json data              | body_reference |
| https://www.azercell.com/assets/files/chat/Privacy%20notice%20for%20web%20-%20AZ%20.docx         | Document    | word document          | body_reference |
| https://www.azercell.com/theme/fonts/icomoon.eot?lv4d96                                          | Font        | embedded opentype font | body_reference |
| https://www.azercell.com/theme/fonts/icomoon.ttf?lv4d96                                          | Font        | truetype font          | body_reference |
| https://www.azercell.com/theme/fonts/LotaGrotesque-Black.woff                                    | Font        | woff font              | body_reference |
| https://www.azercell.com/theme/fonts/LotaGrotesque-Bold.woff                                     | Font        | woff font              | body_reference |
| https://www.azercell.com/theme/fonts/LotaGrotesque-Regular.woff                                  | Font        | woff font              | body_reference |
| https://www.azercell.com/theme/fonts/icomoon.woff?lv4d96                                         | Font        | woff font              | body_reference |
| https://www.azercell.com/theme/fonts/LotaGrotesque-Black.woff2                                   | Font        | woff2 font             | body_reference |
| https://www.azercell.com/theme/fonts/LotaGrotesque-Bold.woff2                                    | Font        | woff2 font             | body_reference |
| https://www.azercell.com/theme/fonts/LotaGrotesque-Regular.woff2                                 | Font        | woff2 font             | body_reference |
| https://www.azercell.com/favicon.ico                                                             | Image       | icon                   | request_url    |
| https://www.azercell.com/theme/images/common/white.jpg                                           | Image       | jpeg image             | body_reference |
| https://www.azercell.com/assets/images/create-a-learning-plan.png                                | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/dg-solution/busuu/updated/bg.png                          | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/dg-solution/busuu/updated/desktop-393x502.png             | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/dg-solution/busuu/updated/desktop-564x566(1).png          | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/dg-solution/busuu/updated/desktop-750x580.png             | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/dg-solution/busuu/updated/mobile-288x444.png              | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/dg-solution/kabinetim/main-page/az.png                    | Image       | png image              | body_reference |
| https://www.azercell.com/assets/images/dg-solution/kabinetim/main-page/azh.png                   | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/dg-solution/kabinetim/main-page/homenaz.png               | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/dg-solution/kids/mosaic-kids.png                          | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/dg-solution/litres/1-desktop-750x580.png                  | Image       | png image              | body_reference |
| https://www.azercell.com/assets/images/dg-solution/litres/1-mobile-288x444.png                   | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/dg-solution/litres/2-desktop-750x580.png                  | Image       | png image              | body_reference |
| https://www.azercell.com/assets/images/dg-solution/litres/2-mobile-288x444.png                   | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/dg-solution/litres/3-desktop-750x580.png                  | Image       | png image              | body_reference |
| https://www.azercell.com/assets/images/dg-solution/litres/3-mobile-288x444.png                   | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/dg-solution/litres/4-desktop-750x580.png                  | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/dg-solution/litres/4-mobile-288x444.png                   | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/dg-solution/litres/564x566_2-1.png                        | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/dg-solution/litres/desktop-audio-new-brandbook.png        | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/dg-solution/litres/device(1).png                          | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/dg-solution/litres/device-new-screenshots.png             | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/dg-solution/yandex-plus/icon-1.png                        | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/dg-solution/yandex-plus/icon2.png                         | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/dg-solution/yandex-plus/icon3.png                         | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/dg-solution/yandex-plus/img2.png                          | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/dg-solution/yandex-plus/music.png                         | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/dg-solution/yandex-plus/yandex-book-en.png                | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/dg-solution/yandex-plus/yandex-muzuki-en.png              | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/dg-solution/yandex-plus/yandexbook-img.png                | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/digital-service/hero-background-1.png                     | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/digital-service/kino-poisk(1).png                         | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/home/home-img.png                                         | Image       | png image              | body_reference |
| https://www.azercell.com/assets/images/imge.png                                                  | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/maste-up-to-12-languages.png                              | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/study-playing.png                                         | Image       | png image              | request_url    |
| https://www.azercell.com/assets/images/track-your-progress.png                                   | Image       | png image              | request_url    |
| https://www.azercell.com/src/images/chat-logo.png                                                | Image       | png image              | body_reference |
| https://www.azercell.com/theme/images/bg/dg-solution-xl.png                                      | Image       | png image              | request_url    |
| https://www.azercell.com/theme/images/common/applogo512.png                                      | Image       | png image              | body_reference |
| https://www.azercell.com/theme/images/common/get-app-image.png                                   | Image       | png image              | body_reference |
| https://www.azercell.com/theme/images/notifications.png                                          | Image       | png image              | body_reference |
| https://www.azercell.com/images/common/b-2-c-logo_purple.svg                                     | Image       | svg image              | body_reference |
| https://www.azercell.com/src/images/chat-back.svg                                                | Image       | svg image              | body_reference |
| https://www.azercell.com/src/images/chat-close.svg                                               | Image       | svg image              | body_reference |
| https://www.azercell.com/src/images/chat-delete.svg                                              | Image       | svg image              | body_reference |
| https://www.azercell.com/src/images/chat-image-upload.svg                                        | Image       | svg image              | body_reference |
| https://www.azercell.com/src/images/chat-send-message.svg                                        | Image       | svg image              | body_reference |
| https://www.azercell.com/theme/fonts/LotaGrotesque-Black.svg                                     | Image       | svg image              | body_reference |
| https://www.azercell.com/theme/fonts/LotaGrotesque-Bold.svg                                      | Image       | svg image              | body_reference |
| https://www.azercell.com/theme/fonts/LotaGrotesque-Regular.svg                                   | Image       | svg image              | body_reference |
| https://www.azercell.com/theme/fonts/icomoon.svg?lv4d96                                          | Image       | svg image              | body_reference |
| https://www.azercell.com/theme/images/bg/main-bg_xl.svg                                          | Image       | svg image              | body_reference |
| https://www.azercell.com/theme/images/common/az.svg                                              | Image       | svg image              | body_reference |
| https://www.azercell.com/theme/images/common/b-2-c-logo.svg                                      | Image       | svg image              | body_reference |
| https://www.azercell.com/theme/images/common/b-2-c-logo_purple.svg                               | Image       | svg image              | body_reference |
| https://www.azercell.com/theme/images/common/en.svg                                              | Image       | svg image              | body_reference |
| https://www.azercell.com/theme/images/common/ru.svg                                              | Image       | svg image              | body_reference |
| https://www.azercell.com/theme/images/icons/appgallery-white.svg                                 | Image       | svg image              | body_reference |
| https://www.azercell.com/theme/images/icons/appgallery.svg                                       | Image       | svg image              | body_reference |
| https://www.azercell.com/theme/images/icons/google-play.svg                                      | Image       | svg image              | body_reference |
| https://www.azercell.com/theme/images/icons/google-play_grey.svg                                 | Image       | svg image              | body_reference |
| https://www.azercell.com/theme/images/icons/icon-error.svg                                       | Image       | svg image              | body_reference |
| https://www.azercell.com/theme/images/icons/icon-success.svg                                     | Image       | svg image              | body_reference |
| https://www.azercell.comtheme/images/common/b-2-c-logo.svg                                       | Image       | svg image              | body_reference |
| https://www.azercell.com/assets/cache/webp/theme/images/kids.png.webp                            | Image       | webp image             | request_url    |
| https://www.azercell.com/assets/cache/webpdg-solution/azercell-kabinetim/648x407.jpg.webp        | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/bookmate/background(1).jpg.webp            | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/bookmate/bg.jpg.webp                       | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/busuu/busuu-portrait-blue-01.jpg.webp      | Image       | webp image             | request_url    |
| https://www.azercell.com/assets/cache/webpdg-solution/busuu/updated/bg(1).png.webp               | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/busuu/updated/bg.png.webp                  | Image       | webp image             | request_url    |
| https://www.azercell.com/assets/cache/webpdg-solution/busuu/updated/lg-tablet-440x524.png.webp   | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/busuu/updated/md-tablet-312x524.png.webp   | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/busuu/updated/xl-desktop-1020x524.png.webp | Image       | webp image             | request_url    |
| https://www.azercell.com/assets/cache/webpdg-solution/kabinetim/main-page/az.png.webp            | Image       | webp image             | request_url    |
| https://www.azercell.com/assets/cache/webpdg-solution/kids/background.jpg.webp                   | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/kids/bg(1).jpg.webp                        | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/kids/bg.jpg.webp                           | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/kids/home-card-kids.png.webp               | Image       | webp image             | request_url    |
| https://www.azercell.com/assets/cache/webpdg-solution/kids/lg.png.webp                           | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/kids/protection-from.png.webp              | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/kids/xl.png.webp                           | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/kinon/1128x402.jpg.webp                    | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/kinon/hero-banner/1024x684.jpg.webp        | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/kinon/hero-banner/1400x684(1).jpg.webp     | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/kinon/hero-banner/320x640(1).jpg.webp      | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/litres/1(1).png.webp                       | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/litres/2(2).png.webp                       | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/litres/3(2).png.webp                       | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/litres/4(2).png.webp                       | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/litres/5(1).png.webp                       | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/litres/6.png.webp                          | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/litres/background.jpg.webp                 | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/litres/book1.jpg.webp                      | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/litres/book2.jpg.webp                      | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/litres/book3.jpg.webp                      | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/litres/digital-apps-page-litres.png.webp   | Image       | webp image             | request_url    |
| https://www.azercell.com/assets/cache/webpdg-solution/litres/group-3.png.webp                    | Image       | webp image             | request_url    |
| https://www.azercell.com/assets/cache/webpdg-solution/litres/image-background-banner.jpg.webp    | Image       | webp image             | request_url    |
| https://www.azercell.com/assets/cache/webpdg-solution/litres/lg-tablet-1.png.webp                | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/litres/md-tablet-1.png.webp                | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/litres/xl-desktop(2).png.webp              | Image       | webp image             | request_url    |
| https://www.azercell.com/assets/cache/webpdg-solution/menu-cards/busuu.jpg.webp                  | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/menu-cards/smsradar.png.webp               | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpdg-solution/yandex-plus/hero-image.png.webp            | Image       | webp image             | request_url    |
| https://www.azercell.com/assets/cache/webpdg-solution/yandex-plus/icon.png.webp                  | Image       | webp image             | request_url    |
| https://www.azercell.com/assets/cache/webpdigital-service/bg-8.jpg.webp                          | Image       | webp image             | request_url    |
| https://www.azercell.com/assets/cache/webpempty-backgrounds/empty-campaign.png.webp              | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpempty-backgrounds/empty-service.png.webp               | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webphome-page/1024x684(3).jpg.webp                         | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webphome-page/1024x684-1.jpg.webp                          | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webphome-page/1400x684(3).jpg.webp                         | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webphome-page/1400x684-1.jpg.webp                          | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webphome-page/320x640(2).jpg.webp                          | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webphome-page/320x640(4).jpg.webp                          | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webphome/1024x684(1).jpg.webp                              | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webphome/1024x684(5).jpg.webp                              | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webphome/1400x684(4).jpg.webp                              | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webphome/1400x684.jpg.webp                                 | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webphome/320x640(1).jpg.webp                               | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webphome/320x640(5).jpg.webp                               | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpmovie-1(1).png.webp                                    | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpmovie-2(1).png.webp                                    | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpmovie-3(1).png.webp                                    | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpservices/paycell-menu-card.png.jpg.webp                | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webpservices/paycell.jpg.webp                              | Image       | webp image             | body_reference |
| https://www.azercell.com/assets/cache/webptariffs/prepaid/452x316.jpg.webp                       | Image       | webp image             | body_reference |


### HTML Meta Tags (first 100)

| Source        | Name         | Value                                                                                                                                                                                                                                                                                                        |
| ------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| charset       | charset      | utf-8                                                                                                                                                                                                                                                                                                        |
| charset       | charset      | utf-8                                                                                                                                                                                                                                                                                                        |
| charset       | charset      | utf-8                                                                                                                                                                                                                                                                                                        |
| charset       | charset      | utf-8                                                                                                                                                                                                                                                                                                        |
| charset       | charset      | utf-8                                                                                                                                                                                                                                                                                                        |
| standard_meta | description  | Azercell-dən fərdi təkliflər - sərfəli tariflər, kampaniyalar və əlçatan xidmətlər. 24/7 Müştəri Xidmətləri. 5 milyondan çox abunəçi.                                                                                                                                                                        |
| standard_meta | description  | Əyləncə və üstünlüklər bir abunə daxilində!                                                                                                                                                                                                                                                                  |
| standard_meta | description  | Azercell Kids ilə övladlarınız əyləncəli şəkildə inkişaf edir. Uşaqlar üçün sevimli cizgi filmləri, personajlar və video oyunlar. Azercell abunəçiləri üçün Azercell Kids tətbiqinə xüsusi abunə şərtləri. İndi abunə olun.                                                                                  |
| standard_meta | description  | Dil öyrənmək üçün ən yaxşı tətbiq. Dünya üzrə 120 milyondan çox istifadəçi. Azercell abunəçiləri üçün Busuu tətbiqinə xüsusi şərtlərə abunə olmaq imkanı. İndi abunə olun.                                                                                                                                   |
| standard_meta | description  | Litres tətbiqi: audiokitablar və elektron kitablar. Litres tətbiqi Azercell abunəçiləri üçün xüsusi abunə şərtləri ilə təqdim edilir. İndi abunə olun.                                                                                                                                                       |
| html_comment  | html_comment | Google Tag Manager                                                                                                                                                                                                                                                                                           |
| html_comment  | html_comment | End Google Tag Manager                                                                                                                                                                                                                                                                                       |
| html_comment  | html_comment | Google Tag Manager (noscript)                                                                                                                                                                                                                                                                                |
| html_comment  | html_comment | End Google Tag Manager (noscript)                                                                                                                                                                                                                                                                            |
| html_comment  | html_comment | countdownBar                                                                                                                                                                                                                                                                                                 |
| html_comment  | html_comment | get app                                                                                                                                                                                                                                                                                                      |
| html_comment  | html_comment | <a href="/az/#repForm" class="top-bar__icon-link"><i
                                    class="icon-wallet-sm"></i></a>                                                                                                                                                                                     |
| html_comment  | html_comment | <img class='lazy' data-src="images/common/b-2-c-logo_purple.svg" alt="b-2-c-logo-purple">                                                                                                                                                                                                                    |
| html_comment  | html_comment | menu                                                                                                                                                                                                                                                                                                         |
| html_comment  | html_comment | <div class="alerts-info" style="background-color: rgba(235, 189, 0, .1); display: none; margin: 10px 0 0; ">
                <i class="icon-info"></i>
                <p>Hörmətli Abunəçi, Xidmətə qoşulmaq üçün mövcud nömrəniz “Azercell”in balansında olmalıdır.
Nömrənizi dəyişmədən “Azercell”ə daşıyı |
| html_comment  | html_comment | !!! qr code logic is not active for now                                                                                                                                                                                                                                                                      |
| html_comment  | html_comment | <div class="pure-g pure-g_modal">
                    
                        <div id="qr-code-wrapper" class="pure-u-1 pure-u-lg-1-2">
                            <h5 class="tabs__title">
                                QR kodundan istifadə et                             </h5>
                     |
| html_comment  | html_comment | <div class="alerts-info" style="background-color: rgba(235, 189, 0, .1) ">
                        <i class="icon-info"></i>
                        <p>Nömrənin cari hesab borcu olmamalıdır. Şəbəkədə ən az <strong>90 gün qalmalısınız</strong>.</p>
                    </div>                           |
| html_comment  | html_comment | Chat Widget HTML                                                                                                                                                                                                                                                                                             |
| html_comment  | html_comment | Chat body                                                                                                                                                                                                                                                                                                    |
| html_comment  | html_comment | Post-chat rating                                                                                                                                                                                                                                                                                             |
| html_comment  | html_comment | Confirmation popup for deleting chat history (Moved Inside Chat Window)                                                                                                                                                                                                                                      |
| html_comment  | html_comment | Image Modal                                                                                                                                                                                                                                                                                                  |
| html_comment  | html_comment | Genesys SDK                                                                                                                                                                                                                                                                                                  |
| html_comment  | html_comment | Chat Widget Logic                                                                                                                                                                                                                                                                                            |
| html_comment  | html_comment | Google Tag Manager                                                                                                                                                                                                                                                                                           |
| html_comment  | html_comment | End Google Tag Manager                                                                                                                                                                                                                                                                                       |
| html_comment  | html_comment | Google Tag Manager (noscript)                                                                                                                                                                                                                                                                                |
| html_comment  | html_comment | End Google Tag Manager (noscript)                                                                                                                                                                                                                                                                            |
| html_comment  | html_comment | countdownBar                                                                                                                                                                                                                                                                                                 |
| html_comment  | html_comment | get app                                                                                                                                                                                                                                                                                                      |
| html_comment  | html_comment | <a href="/az/#repForm" class="top-bar__icon-link"><i
                                    class="icon-wallet-sm"></i></a>                                                                                                                                                                                     |
| html_comment  | html_comment | <img class='lazy' data-src="images/common/b-2-c-logo_purple.svg" alt="b-2-c-logo-purple">                                                                                                                                                                                                                    |
| html_comment  | html_comment | menu                                                                                                                                                                                                                                                                                                         |
| html_comment  | html_comment | <div class="alerts-info" style="background-color: rgba(235, 189, 0, .1); display: none; margin: 10px 0 0; ">
                <i class="icon-info"></i>
                <p>Hörmətli Abunəçi, Xidmətə qoşulmaq üçün mövcud nömrəniz “Azercell”in balansında olmalıdır.
Nömrənizi dəyişmədən “Azercell”ə daşıyı |
| html_comment  | html_comment | !!! qr code logic is not active for now                                                                                                                                                                                                                                                                      |
| html_comment  | html_comment | <div class="pure-g pure-g_modal">
                    
                        <div id="qr-code-wrapper" class="pure-u-1 pure-u-lg-1-2">
                            <h5 class="tabs__title">
                                QR kodundan istifadə et                             </h5>
                     |
| html_comment  | html_comment | <div class="alerts-info" style="background-color: rgba(235, 189, 0, .1) ">
                        <i class="icon-info"></i>
                        <p>Nömrənin cari hesab borcu olmamalıdır. Şəbəkədə ən az <strong>90 gün qalmalısınız</strong>.</p>
                    </div>                           |
| html_comment  | html_comment | Chat Widget HTML                                                                                                                                                                                                                                                                                             |
| html_comment  | html_comment | Chat body                                                                                                                                                                                                                                                                                                    |
| html_comment  | html_comment | Post-chat rating                                                                                                                                                                                                                                                                                             |
| html_comment  | html_comment | Confirmation popup for deleting chat history (Moved Inside Chat Window)                                                                                                                                                                                                                                      |
| html_comment  | html_comment | Image Modal                                                                                                                                                                                                                                                                                                  |
| html_comment  | html_comment | Genesys SDK                                                                                                                                                                                                                                                                                                  |
| html_comment  | html_comment | Chat Widget Logic                                                                                                                                                                                                                                                                                            |
| html_comment  | html_comment | Google Tag Manager                                                                                                                                                                                                                                                                                           |
| html_comment  | html_comment | End Google Tag Manager                                                                                                                                                                                                                                                                                       |
| html_comment  | html_comment | Google Tag Manager (noscript)                                                                                                                                                                                                                                                                                |
| html_comment  | html_comment | End Google Tag Manager (noscript)                                                                                                                                                                                                                                                                            |
| html_comment  | html_comment | countdownBar                                                                                                                                                                                                                                                                                                 |
| html_comment  | html_comment | get app                                                                                                                                                                                                                                                                                                      |
| html_comment  | html_comment | <a href="/az/#repForm" class="top-bar__icon-link"><i
                                    class="icon-wallet-sm"></i></a>                                                                                                                                                                                     |
| html_comment  | html_comment | <img class='lazy' data-src="images/common/b-2-c-logo_purple.svg" alt="b-2-c-logo-purple">                                                                                                                                                                                                                    |
| html_comment  | html_comment | menu                                                                                                                                                                                                                                                                                                         |
| html_comment  | html_comment | <div class="alerts-info" style="background-color: rgba(235, 189, 0, .1); display: none; margin: 10px 0 0; ">
                <i class="icon-info"></i>
                <p>Hörmətli Abunəçi, Xidmətə qoşulmaq üçün mövcud nömrəniz “Azercell”in balansında olmalıdır.
Nömrənizi dəyişmədən “Azercell”ə daşıyı |
| html_comment  | html_comment | !!! qr code logic is not active for now                                                                                                                                                                                                                                                                      |
| html_comment  | html_comment | <div class="pure-g pure-g_modal">
                    
                        <div id="qr-code-wrapper" class="pure-u-1 pure-u-lg-1-2">
                            <h5 class="tabs__title">
                                QR kodundan istifadə et                             </h5>
                     |
| html_comment  | html_comment | <div class="alerts-info" style="background-color: rgba(235, 189, 0, .1) ">
                        <i class="icon-info"></i>
                        <p>Nömrənin cari hesab borcu olmamalıdır. Şəbəkədə ən az <strong>90 gün qalmalısınız</strong>.</p>
                    </div>                           |
| html_comment  | html_comment | Chat Widget HTML                                                                                                                                                                                                                                                                                             |
| html_comment  | html_comment | Chat body                                                                                                                                                                                                                                                                                                    |
| html_comment  | html_comment | Post-chat rating                                                                                                                                                                                                                                                                                             |
| html_comment  | html_comment | Confirmation popup for deleting chat history (Moved Inside Chat Window)                                                                                                                                                                                                                                      |
| html_comment  | html_comment | Image Modal                                                                                                                                                                                                                                                                                                  |
| html_comment  | html_comment | Genesys SDK                                                                                                                                                                                                                                                                                                  |
| html_comment  | html_comment | Chat Widget Logic                                                                                                                                                                                                                                                                                            |
| html_comment  | html_comment | Google Tag Manager                                                                                                                                                                                                                                                                                           |
| html_comment  | html_comment | End Google Tag Manager                                                                                                                                                                                                                                                                                       |
| html_comment  | html_comment | Google Tag Manager (noscript)                                                                                                                                                                                                                                                                                |
| html_comment  | html_comment | End Google Tag Manager (noscript)                                                                                                                                                                                                                                                                            |
| html_comment  | html_comment | countdownBar                                                                                                                                                                                                                                                                                                 |
| html_comment  | html_comment | get app                                                                                                                                                                                                                                                                                                      |
| html_comment  | html_comment | <a href="/az/#repForm" class="top-bar__icon-link"><i
                                    class="icon-wallet-sm"></i></a>                                                                                                                                                                                     |
| html_comment  | html_comment | <img class='lazy' data-src="images/common/b-2-c-logo_purple.svg" alt="b-2-c-logo-purple">                                                                                                                                                                                                                    |
| html_comment  | html_comment | menu                                                                                                                                                                                                                                                                                                         |
| html_comment  | html_comment | <div class="alerts-info" style="background-color: rgba(235, 189, 0, .1); display: none; margin: 10px 0 0; ">
                <i class="icon-info"></i>
                <p>Hörmətli Abunəçi, Xidmətə qoşulmaq üçün mövcud nömrəniz “Azercell”in balansında olmalıdır.
Nömrənizi dəyişmədən “Azercell”ə daşıyı |
| html_comment  | html_comment | !!! qr code logic is not active for now                                                                                                                                                                                                                                                                      |
| html_comment  | html_comment | <div class="pure-g pure-g_modal">
                    
                        <div id="qr-code-wrapper" class="pure-u-1 pure-u-lg-1-2">
                            <h5 class="tabs__title">
                                QR kodundan istifadə et                             </h5>
                     |
| html_comment  | html_comment | <div class="alerts-info" style="background-color: rgba(235, 189, 0, .1) ">
                        <i class="icon-info"></i>
                        <p>Nömrənin cari hesab borcu olmamalıdır. Şəbəkədə ən az <strong>90 gün qalmalısınız</strong>.</p>
                    </div>                           |
| html_comment  | html_comment | Chat Widget HTML                                                                                                                                                                                                                                                                                             |
| html_comment  | html_comment | Chat body                                                                                                                                                                                                                                                                                                    |
| html_comment  | html_comment | Post-chat rating                                                                                                                                                                                                                                                                                             |
| html_comment  | html_comment | Confirmation popup for deleting chat history (Moved Inside Chat Window)                                                                                                                                                                                                                                      |
| html_comment  | html_comment | Image Modal                                                                                                                                                                                                                                                                                                  |
| html_comment  | html_comment | Genesys SDK                                                                                                                                                                                                                                                                                                  |
| html_comment  | html_comment | Chat Widget Logic                                                                                                                                                                                                                                                                                            |
| html_comment  | html_comment | Google Tag Manager                                                                                                                                                                                                                                                                                           |
| html_comment  | html_comment | End Google Tag Manager                                                                                                                                                                                                                                                                                       |
| html_comment  | html_comment | Google Tag Manager (noscript)                                                                                                                                                                                                                                                                                |
| html_comment  | html_comment | End Google Tag Manager (noscript)                                                                                                                                                                                                                                                                            |
| html_comment  | html_comment | countdownBar                                                                                                                                                                                                                                                                                                 |
| html_comment  | html_comment | get app                                                                                                                                                                                                                                                                                                      |
| html_comment  | html_comment | <a href="/az/#repForm" class="top-bar__icon-link"><i
                                    class="icon-wallet-sm"></i></a>                                                                                                                                                                                     |
| html_comment  | html_comment | <img class='lazy' data-src="images/common/b-2-c-logo_purple.svg" alt="b-2-c-logo-purple">                                                                                                                                                                                                                    |
| html_comment  | html_comment | menu                                                                                                                                                                                                                                                                                                         |
| html_comment  | html_comment | <div class="alerts-info" style="background-color: rgba(235, 189, 0, .1); display: none; margin: 10px 0 0; ">
                <i class="icon-info"></i>
                <p>Hörmətli Abunəçi, Xidmətə qoşulmaq üçün mövcud nömrəniz “Azercell”in balansında olmalıdır.
Nömrənizi dəyişmədən “Azercell”ə daşıyı |


---

## Subdomain Enumeration

### Enumeration Sources

| Source           | Count | Error                                                                                                                       |
| ---------------- | ----- | --------------------------------------------------------------------------------------------------------------------------- |
| crtname          | 100   |                                                                                                                             |
| wayback          | 89    |                                                                                                                             |
| rapiddns         | 36    |                                                                                                                             |
| otx_urls         | 12    |                                                                                                                             |
| certspotter      | 9     |                                                                                                                             |
| urlscan          | 1     |                                                                                                                             |
| urlscan_urls     | 1     |                                                                                                                             |
| anubis           | 0     | anubis: authentication failed - check your API key(s) in api_keys.json                                                      |
| censys           | 0     | skipped: missing API key(s): censys_id, censys_secret (add to api_keys.json)                                                |
| chaos            | 0     | skipped: missing API key(s): chaos_key (add to api_keys.json)                                                               |
| circl            | 0     | skipped: missing API key(s): circl_user, circl_pass (add to api_keys.json)                                                  |
| commoncrawl      | 0     | commoncrawl: could not fetch index list: core.utils.request_with_retry() got multiple values for keyword argument 'timeout' |
| commoncrawl_urls | 0     | [CC-URLs] Could not fetch index list: core.utils.request_with_retry() got multiple values for keyword argument 'timeout'    |
| crtsh            | 0     | crtsh request failed: 502 Server Error: Bad Gateway for url: https://crt.sh/?q=%25.azercell.com&output=json                 |
| dnsdumpster      | 0     | [DNSDumpster] Could not extract CSRF token.                                                                                 |
| hackertarget     | 0     |                                                                                                                             |
| otx              | 0     |                                                                                                                             |
| securitytrails   | 0     | skipped: missing API key(s): securitytrails (add to api_keys.json)                                                          |
| shodan           | 0     | skipped: missing API key(s): shodan (add to api_keys.json)                                                                  |
| virustotal       | 0     | skipped: missing API key(s): virustotal (add to api_keys.json)                                                              |
| wayback_urls     | 0     |                                                                                                                             |


### Statistics

- **Total Subdomains:** 164

- **Live (HTTPS):** 33

- **Live (HTTP):** 39

- **Potential Takeovers:** 0



### All Subdomains

| Subdomain                         | IPs                                                                                                                                  | HTTPS | HTTP | Final URL (HTTPS) | HTTPS Error | HTTP Error |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | ----- | ---- | ----------------- | ----------- | ---------- |
| 1.azercell.com                    | []                                                                                                                                   |       |      |                   |             |            |
| 3g-t.azercell.com                 | []                                                                                                                                   |       |      |                   |             |            |
| 3gmax.azercell.com                | []                                                                                                                                   |       |      |                   |             |            |
| 554-smtp1.azercell.com            | []                                                                                                                                   |       |      |                   |             |            |
| 554-smtp2.azercell.com            | []                                                                                                                                   |       |      |                   |             |            |
| account.azercell.com              | []                                                                                                                                   |       |      |                   |             |            |
| aicweb.azercell.com               | []                                                                                                                                   |       |      |                   |             |            |
| alumni.azercell.com               | []                                                                                                                                   |       |      |                   |             |            |
| api.azercell.com                  | ["5.191.90.101"]                                                                                                                     |       | 302  |                   | CONN        |            |
| appforms.azercell.com             | []                                                                                                                                   |       |      |                   |             |            |
| apps.dbss.pr.azercell.com         | []                                                                                                                                   |       |      |                   |             |            |
| apps.tst3.dbss.azercell.com       | []                                                                                                                                   |       |      |                   |             |            |
| apps.tst4.dbss.azercell.com       | []                                                                                                                                   |       |      |                   |             |            |
| ascomapp.azercell.com             | []                                                                                                                                   |       |      |                   |             |            |
| autodiscover.azercell.com         | ["40.103.64.232", "40.104.134.8", "40.99.128.248", "52.97.112.152", "52.97.112.216", "52.97.97.104", "52.98.142.8", "52.98.143.232"] |       | 301  |                   | CONN        |            |
| azercelliler.azercell.com         | []                                                                                                                                   |       |      |                   |             |            |
| azercellliler.azercell.com        | []                                                                                                                                   |       |      |                   |             |            |
| b2b-api.azercell.com              | ["5.191.90.105"]                                                                                                                     | 404   | 302  |                   |             |            |
| barama-t.azercell.com             | []                                                                                                                                   |       |      |                   |             |            |
| bizklub.azercell.com              | []                                                                                                                                   |       |      |                   |             |            |
| biznes.azercell.com               | ["5.191.90.105"]                                                                                                                     | 200   | 302  |                   |             |            |
| blog-tst.azercell.com             | []                                                                                                                                   |       |      |                   |             |            |
| blog.azercell.com                 | []                                                                                                                                   |       |      |                   |             |            |
| busuu.azercell.com                | ["5.191.90.105"]                                                                                                                     | 200   | 302  |                   |             |            |
| busuu2.azercell.com               | ["217.25.25.40", "217.25.25.49"]                                                                                                     | 503   | 503  |                   |             |            |
| cacti.azercell.com                | []                                                                                                                                   |       |      |                   |             |            |
| careers.azercell.com              | ["5.191.90.105"]                                                                                                                     | 301   | 302  |                   |             |            |
| cdn.azercell.com                  | ["5.191.90.105"]                                                                                                                     | 404   | 302  |                   |             |            |
| chat.azercell.com                 | []                                                                                                                                   |       |      |                   |             |            |
| chatbot-api-dev.azercell.com      | ["5.191.90.101"]                                                                                                                     |       | 302  |                   | CONN        |            |
| cinema.azercell.com               | []                                                                                                                                   |       |      |                   |             |            |
| cm.azercell.com                   | []                                                                                                                                   |       |      |                   |             |            |
| company.azercell.com              | []                                                                                                                                   |       |      |                   |             |            |
| container2.azercell.com           | []                                                                                                                                   |       |      |                   |             |            |
| corporate.azercell.com            | []                                                                                                                                   |       |      |                   |             |            |
| corpsteam.azercell.com            | []                                                                                                                                   |       |      |                   |             |            |
| crm.azercell.com                  | []                                                                                                                                   |       |      |                   |             |            |
| crmmailgw.azercell.com            | []                                                                                                                                   |       |      |                   |             |            |
| csr.apps.dbss.pr.azercell.com     | []                                                                                                                                   |       |      |                   |             |            |
| csr.apps.tst3.dbss.azercell.com   | []                                                                                                                                   |       |      |                   |             |            |
| db.azercell.com                   | []                                                                                                                                   |       |      |                   |             |            |
| dbss.azercell.com                 | []                                                                                                                                   |       |      |                   |             |            |
| dbss.pr.azercell.com              | []                                                                                                                                   |       |      |                   |             |            |
| dealerexpress.azercell.com        | ["5.191.90.105"]                                                                                                                     | 200   | 302  |                   |             |            |
| dealeronline.azercell.com         | ["5.191.90.86"]                                                                                                                      | 301   | 301  |                   |             |            |
| dialin.azercell.com               | []                                                                                                                                   |       |      |                   |             |            |
| docs.azercell.com                 | ["5.191.90.101"]                                                                                                                     | 404   | 302  |                   |             |            |
| es.azercell.com                   | ["5.191.90.101"]                                                                                                                     | 404   | 302  |                   |             |            |
| esim.azercell.com                 | ["5.191.90.102"]                                                                                                                     | 303   | 302  |                   |             |            |
| eslab.azercell.com                | ["5.191.90.101"]                                                                                                                     | 404   | 302  |                   |             |            |
| ess.azercell.com                  | []                                                                                                                                   |       |      |                   |             |            |
| etender.azercell.com              | []                                                                                                                                   |       |      |                   |             |            |
| expresswaye.azercell.com          | ["5.191.90.96"]                                                                                                                      |       |      |                   | TIMEOUT     | TIMEOUT    |
| faq1.azercell.com                 | []                                                                                                                                   |       |      |                   |             |            |
| fleet.azercell.com                | ["5.191.90.102"]                                                                                                                     | 200   | 302  |                   |             |            |
| gateway.azercell.com              | []                                                                                                                                   |       |      |                   |             |            |
| gwazol.azercell.com               | []                                                                                                                                   |       |      |                   |             |            |
| gwazol2.azercell.com              | []                                                                                                                                   |       |      |                   |             |            |
| hc-sec01.azercell.com             | []                                                                                                                                   |       |      |                   |             |            |
| hc-sec02.azercell.com             | []                                                                                                                                   |       |      |                   |             |            |
| hostmaster.azercell.com           | []                                                                                                                                   |       |      |                   |             |            |
| http.azercell.com                 | []                                                                                                                                   |       |      |                   |             |            |
| ice.azercell.com                  | ["5.191.90.101"]                                                                                                                     | 301   | 302  |                   |             |            |
| idealab.azercell.com              | []                                                                                                                                   |       |      |                   |             |            |
| insurance.azercell.com            | []                                                                                                                                   |       |      |                   |             |            |
| internal.azercell.com             | []                                                                                                                                   |       |      |                   |             |            |
| internet.azercell.com             | ["5.191.90.102"]                                                                                                                     | 302   | 404  |                   |             |            |
| intracell.azercell.com            | []                                                                                                                                   |       |      |                   |             |            |
| kabinetim-app.azercell.com        | ["5.191.90.102"]                                                                                                                     | 302   | 302  |                   |             |            |
| kabinetim.azercell.com            | ["5.191.90.102"]                                                                                                                     | 200   | 302  |                   |             |            |
| kc.azercell.com                   | ["5.191.90.86"]                                                                                                                      | 502   | 301  |                   |             |            |
| kids.azercell.com                 | ["5.191.90.105"]                                                                                                                     | 200   | 302  |                   |             |            |
| l15.azercell.com                  | []                                                                                                                                   |       |      |                   |             |            |
| link.azercell.com                 | ["5.191.90.105"]                                                                                                                     | 200   | 302  |                   |             |            |
| loyaltygateway.azercell.com       | ["5.191.90.86"]                                                                                                                      | 200   | 301  |                   |             |            |
| lwebconf01.azercell.com           | []                                                                                                                                   |       |      |                   |             |            |
| lyncdiscover.azercell.com         | ["5.191.90.73"]                                                                                                                      |       |      |                   | TIMEOUT     | TIMEOUT    |
| lyncdiscoverinternal.azercell.com | []                                                                                                                                   |       |      |                   |             |            |
| m.azercell.com                    | []                                                                                                                                   |       |      |                   |             |            |
| mailgw-a.azercell.com             | ["217.168.177.101"]                                                                                                                  |       |      |                   | TIMEOUT     | TIMEOUT    |
| mailgw.azercell.com               | ["5.191.90.6"]                                                                                                                       |       |      |                   | TIMEOUT     | TIMEOUT    |
| meet.azercell.com                 | []                                                                                                                                   |       |      |                   |             |            |
| mm.azercell.com                   | []                                                                                                                                   |       |      |                   |             |            |
| mmm.azercell.com                  | []                                                                                                                                   |       |      |                   |             |            |
| mms.azercell.com                  | []                                                                                                                                   |       |      |                   |             |            |
| mmsfoto.azercell.com              | []                                                                                                                                   |       |      |                   |             |            |
| mnpfd.azercell.com                | []                                                                                                                                   |       |      |                   |             |            |
| mo.azercell.com                   | []                                                                                                                                   |       |      |                   |             |            |
| ms.azercell.com                   | []                                                                                                                                   |       |      |                   |             |            |
| naicweb.azercell.com              | []                                                                                                                                   |       |      |                   |             |            |
| nextcloud.azercell.com            | ["5.191.90.101"]                                                                                                                     | 302   | 302  |                   |             |            |
| ns.azercell.com                   | ["5.191.90.41"]                                                                                                                      |       |      |                   | TIMEOUT     | TIMEOUT    |
| ns1.azercell.com                  | ["5.191.90.41"]                                                                                                                      |       |      |                   | TIMEOUT     | TIMEOUT    |
| ns2.azercell.com                  | ["5.191.90.42"]                                                                                                                      |       |      |                   | TIMEOUT     | TIMEOUT    |
| onair.azercell.com                | []                                                                                                                                   |       |      |                   |             |            |
| pbx.azercell.com                  | ["5.191.90.101"]                                                                                                                     |       | 302  |                   | CONN        |            |
| personal.azercell.com             | []                                                                                                                                   |       |      |                   |             |            |
| personalpacks.azercell.com        | []                                                                                                                                   |       |      |                   |             |            |
| phone.azercell.com                | []                                                                                                                                   |       |      |                   |             |            |
| play.azercell.com                 | []                                                                                                                                   |       |      |                   |             |            |
| portal.azercell.com               | []                                                                                                                                   |       |      |                   |             |            |
| pr.azercell.com                   | []                                                                                                                                   |       |      |                   |             |            |
| preview.azercell.com              | []                                                                                                                                   |       |      |                   |             |            |
| project.azercell.com              | []                                                                                                                                   |       |      |                   |             |            |
| pvwa.azercell.com                 | []                                                                                                                                   |       |      |                   |             |            |
| r.azercell.com                    | []                                                                                                                                   |       |      |                   |             |            |
| ravpn.azercell.com                | ["5.191.90.254"]                                                                                                                     | 200   | 504  |                   |             |            |
| rhsso.azercell.com                | ["5.191.90.101"]                                                                                                                     | 200   | 302  |                   |             |            |
| rhssotest.azercell.com            | []                                                                                                                                   |       |      |                   |             |            |
| roaming.azercell.com              | []                                                                                                                                   |       |      |                   |             |            |
| sccm16.azercell.com               | []                                                                                                                                   |       |      |                   |             |            |
| sip.azercell.com                  | ["5.191.90.73"]                                                                                                                      |       |      |                   | TIMEOUT     | TIMEOUT    |
| skype.azercell.com                | []                                                                                                                                   |       |      |                   |             |            |
| skype01.azercell.com              | []                                                                                                                                   |       |      |                   |             |            |
| sms.azercell.com                  | []                                                                                                                                   |       |      |                   |             |            |
| smtp.azercell.com                 | []                                                                                                                                   |       |      |                   |             |            |
| smtp1.azercell.com                | ["5.191.90.87"]                                                                                                                      |       | 504  |                   | TIMEOUT     |            |
| smtp2.azercell.com                | ["5.191.90.88"]                                                                                                                      |       | 504  |                   | TIMEOUT     |            |
| sorgu.azercell.com                | ["5.191.90.86"]                                                                                                                      | 200   | 301  |                   |             |            |
| speedtest.azercell.com            | []                                                                                                                                   |       |      |                   |             |            |
| speedtest01.azercell.com          | []                                                                                                                                   |       |      |                   |             |            |
| speedtest02.azercell.com          | ["5.191.2.142"]                                                                                                                      |       |      |                   | TIMEOUT     | TIMEOUT    |
| splash.azercell.com               | []                                                                                                                                   |       |      |                   |             |            |
| sso.apps.tst4.dbss.azercell.com   | ["5.191.90.101"]                                                                                                                     | 200   | 302  |                   |             |            |
| stats.azercell.com                | []                                                                                                                                   |       |      |                   |             |            |
| subscriber.azercell.com           | []                                                                                                                                   |       |      |                   |             |            |
| support.azercell.com              | ["5.191.90.101"]                                                                                                                     | 302   | 302  |                   |             |            |
| survey.azercell.com               | ["5.191.90.101"]                                                                                                                     | 200   | 302  |                   |             |            |
| survey1.azercell.com              | []                                                                                                                                   |       |      |                   |             |            |
| syslogd.azercell.com              | []                                                                                                                                   |       |      |                   |             |            |
| teknofest.azercell.com            | []                                                                                                                                   |       |      |                   |             |            |
| test999.azercell.com              | []                                                                                                                                   |       |      |                   |             |            |
| tst3.dbss.azercell.com            | []                                                                                                                                   |       |      |                   |             |            |
| tst4.dbss.azercell.com            | []                                                                                                                                   |       |      |                   |             |            |
| tvshows.azercell.com              | ["5.191.90.86"]                                                                                                                      | 404   | 301  |                   |             |            |
| vcc.azercell.com                  | []                                                                                                                                   |       |      |                   |             |            |
| vd.azercell.com                   | []                                                                                                                                   |       |      |                   |             |            |
| vdi.azercell.com                  | []                                                                                                                                   |       |      |                   |             |            |
| vis.azercell.com                  | []                                                                                                                                   |       |      |                   |             |            |
| vis01.azercell.com                | []                                                                                                                                   |       |      |                   |             |            |
| vmx.azercell.com                  | []                                                                                                                                   |       |      |                   |             |            |
| vpngw.azercell.com                | []                                                                                                                                   |       |      |                   |             |            |
| w.azercell.com                    | []                                                                                                                                   |       |      |                   |             |            |
| wap.azercell.com                  | []                                                                                                                                   |       |      |                   |             |            |
| webchat.azercell.com              | ["5.191.90.105"]                                                                                                                     | 404   | 302  |                   |             |            |
| wic.azercell.com                  | ["5.191.90.101"]                                                                                                                     | 200   | 302  |                   |             |            |
| wm.azercell.com                   | []                                                                                                                                   |       |      |                   |             |            |
| wmail.azercell.com                | ["5.191.90.65"]                                                                                                                      | 302   | 504  |                   |             |            |
| ww.azercell.com                   | []                                                                                                                                   |       |      |                   |             |            |
| ww1.azercell.com                  | []                                                                                                                                   |       |      |                   |             |            |
| www.azercell.com                  | ["5.191.90.102"]                                                                                                                     | 302   | 302  |                   |             |            |
| www.es.azercell.com               | []                                                                                                                                   |       |      |                   |             |            |
| www.eslab.azercell.com            | []                                                                                                                                   |       |      |                   |             |            |
| www.mms.azercell.com              | []                                                                                                                                   |       |      |                   |             |            |
| www.ms.azercell.com               | []                                                                                                                                   |       |      |                   |             |            |
| www.ravpn.azercell.com            | []                                                                                                                                   |       |      |                   |             |            |
| www.skype.azercell.com            | []                                                                                                                                   |       |      |                   |             |            |
| www.teknofest.azercell.com        | []                                                                                                                                   |       |      |                   |             |            |
| www.www.azercell.com              | []                                                                                                                                   |       |      |                   |             |            |
| www1.azercell.com                 | []                                                                                                                                   |       |      |                   |             |            |
| wwww.azercell.com                 | []                                                                                                                                   |       |      |                   |             |            |
| xidmetlerim.azercell.com          | []                                                                                                                                   |       |      |                   |             |            |
| zengim.azercell.com               | []                                                                                                                                   |       |      |                   |             |            |
| zengimcell.azercell.com           | []                                                                                                                                   |       |      |                   |             |            |


---

## Wayback Machine

- **Tool:** WebArchive Scanner

- **Timestamp:** 2026-10-08T10:45:38.559304Z


### Summary

- **Total URLs Archived:** 3554

- **Subdomains Discovered:** 20

- **Critical Pattern Hits:** 27

- **Interesting Files:** 24


### Discovered Subdomains

- http://internet.azercell.com

- http://rhssotest.azercell.com

- http://sms.azercell.com

- https://busuu.azercell.com

- https://careers.azercell.com

- https://cdn.azercell.com

- https://csr.apps.dbss.pr.azercell.com

- https://csr.apps.tst3.dbss.azercell.com

- https://esim.azercell.com

- https://fleet.azercell.com

- https://ice.azercell.com

- https://intracell.azercell.com

- https://kabinetim.azercell.com

- https://kids.azercell.com

- https://link.azercell.com

- https://loyaltygateway.azercell.com

- https://pvwa.azercell.com

- https://rhsso.azercell.com

- https://sorgu.azercell.com

- https://support.azercell.com



### Critical Pattern Matches

| Pattern       | URL                                                                                                                                       |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| account       | https://csr.apps.tst3.dbss.azercell.com/tenant1/account/3120957/3/billing/usages                                                          |
| health-check  | https://www.azercell.com/az/about-us/sustainability/environment-and-health/health-and-safety.html                                         |
| health-check  | https://azercell.com/en/about-us/azercell_academy/health-and-safety/basics-of-firefighting.html                                           |
| health-check  | https://www.azercell.com/ru/about-us/azercell_academy/health-and-safety/first-aid-and-cpr.html                                            |
| health-check  | https://www.azercell.com/ru/about-us/azercell_academy/health-and-safety/ohs-awareness.html                                                |
| health-check  | https://www.azercell.com/ru/about-us/sustainability/environment-and-health/health-and-safety.html                                         |
| health-check  | https://www.azercell.com/ru/about-us/azercell_academy/health-and-safety/basics-of-firefighting.html                                       |
| health-check  | https://www.azercell.com/ru/about-us/azercell_academy/health-and-safety/defensive-driving.html                                            |
| info-endpoint | https://www.azercell.com/az/about-us/press-releases/news/informatika-ezr-olimpiadalara-hazirliq-qruplarina-secm-imtahanlar-kecirilib.html |
| info-endpoint | https://www.azercell.com/en/about-us/press-releases/news/informatika-uzre-daha-4-medal.html                                               |
| info-endpoint | https://www.azercell.com/ru/about-us/press-releases/news/informatika-ezr-olimpiadalara-hazirliq-qruplarina-secm-imtahanlar-kecirilib.html |
| info-endpoint | https://azercell.com/ru/corporate/cloud-services/infohub.html                                                                             |
| info-endpoint | https://azercell.com/az/corporate/cloud-services/infohub.html                                                                             |
| info-endpoint | https://www.azercell.com/en/personal/plans-and-services/services-and-options/messages/infocell.html                                       |
| login         | https://support.azercell.com/servicedesk/customer/user/login?destination=portals                                                          |
| login         | https://support.azercell.com/servicedesk/customer/user/login?destination=portals%3F_%3D1                                                  |
| robots-txt    | https://www.azercell.com/robots.txt                                                                                                       |
| robots-txt    | https://azercell.com/robots.txt                                                                                                           |
| robots-txt    | https://busuu.azercell.com/robots.txt                                                                                                     |
| robots-txt    | https://careers.azercell.com/robots.txt                                                                                                   |
| robots-txt    | https://esim.azercell.com/robots.txt                                                                                                      |
| robots-txt    | https://fleet.azercell.com/robots.txt                                                                                                     |
| robots-txt    | https://kids.azercell.com/robots.txt                                                                                                      |
| robots-txt    | https://support.azercell.com/robots.txt                                                                                                   |
| robots-txt    | http://www.azercell.com/robots.txt                                                                                                        |
| robots-txt    | https://ice.azercell.com/robots.txt                                                                                                       |
| robots-txt    | http://internet.azercell.com/robots.txt                                                                                                   |


### Interesting Files

- http://internet.azercell.com/robots.txt

- http://www.azercell.com/robots.txt

- https://azercell.com/robots.txt

- https://busuu.azercell.com/robots.txt

- https://careers.azercell.com/llms.txt?locale=en_US

- https://careers.azercell.com/robots.txt

- https://esim.azercell.com/robots.txt

- https://fleet.azercell.com/robots.txt

- https://ice.azercell.com/robots.txt

- https://kids.azercell.com/llms.txt

- https://kids.azercell.com/robots.txt

- https://support.azercell.com/robots.txt

- https://www.azercell.com/assets/files/acell-roaming-ru1.pdf

- https://www.azercell.com/assets/files/acell-roaming_az_new1.pdf

- https://www.azercell.com/assets/files/awards/azercell-10004.pdf

- https://www.azercell.com/assets/files/roaming/acell-roaming-en(2).pdf

- https://www.azercell.com/assets/files/sms-configurations/acell-sms-ru.pdf

- https://www.azercell.com/assets/files/tiktok-novruz/azercell_tiktok_contest_ru.pdf

- https://www.azercell.com/az/llms.txt

- https://www.azercell.com/az/media/html/files/instagram_eng.pdf

- https://www.azercell.com/llms.txt

- https://www.azercell.com/media/html/files/Instagram_ENG.pdf

- https://www.azercell.com/media/html/files/instagram_eng.pdf

- https://www.azercell.com/robots.txt



### URL Parameters

| Parameter     | Count | Sensitive |
| ------------- | ----- | --------- |
| sortdirection | 6     | ⚠️ Yes    |
| page          | 82    | No        |
| q             | 7     | No        |
| sortcolumn    | 6     | No        |
| utm_source    | 5     | No        |
| utm_medium    | 5     | No        |
| utm_campaign  | 5     | No        |
| locale        | 3     | No        |
| lang          | 3     | No        |
| cmnd          | 3     | No        |
| gad_source    | 2     | No        |
| gclid         | 2     | No        |
| destination   | 2     | No        |
| utm_id        | 1     | No        |


---

## Email Security

### DNS Security

#### SPF

- **Record:** `v=spf1 ip4:217.168.177.101 ip4:5.191.90.6 ip4:5.191.90.87 ip4:5.191.90.88 a mx a:mailgw.azercell.com a:mailgw-a.azercell.com a:smtp1.azercell.com a:smtp2.azercell.com mx:azercell.com include:spf.protection.outlook.com include:_spf.anpdm.com -all`

- **All Qualifier:** `fail`

- **Include Count:** 2

- **Issues:** None ✅


#### DKIM

- **Selectors Found:** default, s1, s2

- **Issues:** None ✅


#### DMARC

- **Record:** `v=DMARC1; p=none; rua=mailto:postmaster@azercell.com`

- **Policy:** none

- **Subdomain Policy:** none

- **PCT:** 100

- **RUA:** mailto:postmaster@azercell.com

- ⚠️ DMARC policy is 'none' - monitoring only, no enforcement against spoofed mail


#### Spoofing Risk

- **Score:** 40

- **Level:** MEDIUM


#### BIMI
- {'record': None, 'logo_url': None, 'vmc_url': None, 'issues': ['No BIMI record found']}


#### DANE (Email)
- {'mx_dane': [{'host': 'smtp1.azercell.com', 'tlsa_name': '_25._tcp.smtp1.azercell.com', 'records': [], 'dane_enabled': False}, {'host': 'smtp2.azercell.com', 'tlsa_name': '_25._tcp.smtp2.azercell.com', 'records': [], 'dane_enabled': False}], 'issues': ["No DANE/TLSA record for 'smtp1.azercell.com' - TLS certificate cannot be pinned via DNS", "No DANE/TLSA record for 'smtp2.azercell.com' - TLS certificate cannot be pinned via DNS"]}


### Email Provider & Gateways

- **Provider:** {"name": "Self-hosted / Unknown", "confidence": 0.3, "mx_hosts": ["smtp1.azercell.com", "smtp2.azercell.com"], "matched_signature": null}


### SMTP Service Configuration

- **Port Scan:** {'hosts': [{'host': 'smtp1.azercell.com', 'ports': [{'port': 25, 'label': 'SMTP', 'protocol': 'SMTP', 'tls': False, 'open': True, 'banner': '220 smtp1.azercell.com ESMTP Thu,  8 Oct 2026 14:44:37 +0400', 'starttls': True, 'error': None}, {'port': 465, 'label': 'SMTPS', 'protocol': 'SMTPS', 'tls': True, 'open': False, 'banner': None, 'starttls': None, 'error': ''}, {'port': 587, 'label': 'SMTP Submission', 'protocol': 'SMTP', 'tls': False, 'open': False, 'banner': None, 'starttls': None, 'error': ''}, {'port': 2525, 'label': 'SMTP Alt', 'protocol': 'SMTP', 'tls': False, 'open': False, 'banner': None, 'starttls': None, 'error': ''}, {'port': 143, 'label': 'IMAP', 'protocol': 'IMAP', 'tls': False, 'open': False, 'banner': None, 'starttls': None, 'error': ''}, {'port': 993, 'label': 'IMAPS', 'protocol': 'IMAPS', 'tls': True, 'open': False, 'banner': None, 'starttls': None, 'error': ''}, {'port': 110, 'label': 'POP3', 'protocol': 'POP3', 'tls': False, 'open': False, 'banner': None, 'starttls': None, 'error': ''}, {'port': 995, 'label': 'POP3S', 'protocol': 'POP3S', 'tls': True, 'open': False, 'banner': None, 'starttls': None, 'error': ''}, {'port': 4190, 'label': 'ManageSieve', 'protocol': 'SIEVE', 'tls': False, 'open': False, 'banner': None, 'starttls': None, 'error': ''}]}, {'host': 'smtp2.azercell.com', 'ports': [{'port': 25, 'label': 'SMTP', 'protocol': 'SMTP', 'tls': False, 'open': True, 'banner': '220 smtp2.azercell.com ESMTP Thu,  8 Oct 2026 14:44:41 +0400', 'starttls': True, 'error': None}, {'port': 465, 'label': 'SMTPS', 'protocol': 'SMTPS', 'tls': True, 'open': False, 'banner': None, 'starttls': None, 'error': ''}, {'port': 587, 'label': 'SMTP Submission', 'protocol': 'SMTP', 'tls': False, 'open': False, 'banner': None, 'starttls': None, 'error': ''}, {'port': 2525, 'label': 'SMTP Alt', 'protocol': 'SMTP', 'tls': False, 'open': False, 'banner': None, 'starttls': None, 'error': ''}, {'port': 143, 'label': 'IMAP', 'protocol': 'IMAP', 'tls': False, 'open': False, 'banner': None, 'starttls': None, 'error': ''}, {'port': 993, 'label': 'IMAPS', 'protocol': 'IMAPS', 'tls': True, 'open': False, 'banner': None, 'starttls': None, 'error': ''}, {'port': 110, 'label': 'POP3', 'protocol': 'POP3', 'tls': False, 'open': False, 'banner': None, 'starttls': None, 'error': ''}, {'port': 995, 'label': 'POP3S', 'protocol': 'POP3S', 'tls': True, 'open': False, 'banner': None, 'starttls': None, 'error': ''}, {'port': 4190, 'label': 'ManageSieve', 'protocol': 'SIEVE', 'tls': False, 'open': False, 'banner': None, 'starttls': None, 'error': ''}]}], 'issues': []}

- **SMTP Enum:** {'hosts': [{'host': 'smtp1.azercell.com', 'connected': True, 'error': None, 'commands': [{'cmd': 'VRFY root', 'key': 'VRFY root', 'response': '252 2.5.2 Cannot VRFY user; try RCPT to attempt delivery', 'code': '252'}, {'cmd': 'VRFY admin', 'key': 'VRFY admin', 'response': '252 2.5.2 Cannot VRFY user; try RCPT to attempt delivery', 'code': '252'}, {'cmd': 'EXPN root', 'key': 'EXPN root', 'response': '500 5.5.1 Command unrecognized: "EXPN root"', 'code': '500'}, {'cmd': 'EXPN all', 'key': 'EXPN all', 'response': '500 5.5.1 Command unrecognized: "EXPN all"', 'code': '500'}, {'cmd': 'RCPT TO:<root@localhost>', 'key': 'RCPT TO root@localhost', 'response': '250 2.1.5 Recipient ok', 'code': '250'}, {'cmd': 'RCPT TO:<admin@localhost>', 'key': 'RCPT TO admin@localhost', 'response': '250 2.1.5 Recipient ok', 'code': '250'}], 'vrfy_enabled': False, 'expn_enabled': False}, {'host': 'smtp2.azercell.com', 'connected': True, 'error': None, 'commands': [{'cmd': 'VRFY root', 'key': 'VRFY root', 'response': '252 2.5.2 Cannot VRFY user; try RCPT to attempt delivery', 'code': '252'}, {'cmd': 'VRFY admin', 'key': 'VRFY admin', 'response': '252 2.5.2 Cannot VRFY user; try RCPT to attempt delivery', 'code': '252'}, {'cmd': 'EXPN root', 'key': 'EXPN root', 'response': '500 5.5.1 Command unrecognized: "EXPN root"', 'code': '500'}, {'cmd': 'EXPN all', 'key': 'EXPN all', 'response': '500 5.5.1 Command unrecognized: "EXPN all"', 'code': '500'}, {'cmd': 'RCPT TO:<root@localhost>', 'key': 'RCPT TO root@localhost', 'response': '250 2.1.5 Recipient ok', 'code': '250'}, {'cmd': 'RCPT TO:<admin@localhost>', 'key': 'RCPT TO admin@localhost', 'response': '250 2.1.5 Recipient ok', 'code': '250'}], 'vrfy_enabled': False, 'expn_enabled': False}], 'issues': []}

- **Catch-All:** {'enabled': True, 'probe_address': 'oxsium-probe-no-such-user-xqz9@azercell.com', 'tested_host': 'smtp1.azercell.com', 'issues': ['Catch-all is enabled on smtp1.azercell.com - accepts mail for any address, increases spam exposure and makes email harvesting easier']}

- **Auth Mechanisms:** {'hosts': [{'host': 'smtp1.azercell.com', 'advertised': [], 'plain_text_allowed': False, 'anonymous_allowed': False}, {'host': 'smtp2.azercell.com', 'advertised': [], 'plain_text_allowed': False, 'anonymous_allowed': False}], 'issues': []}

- **Open Relay:** {'hosts': [{'host': 'smtp1.azercell.com', 'open_relay': False, 'relay_response': '550 5.7.1 Relaying denied'}, {'host': 'smtp2.azercell.com', 'open_relay': False, 'relay_response': '550 5.7.1 Relaying denied'}], 'issues': []}

- **STARTTLS Downgrade:** {'hosts': [{'host': 'smtp1.azercell.com', 'starttls_offered': True, 'downgrade_possible': True, 'plain_data_accepted': True}, {'host': 'smtp2.azercell.com', 'starttls_offered': True, 'downgrade_possible': True, 'plain_data_accepted': True}], 'issues': ['smtp1.azercell.com offers STARTTLS but allows MAIL FROM before TLS negotiation - STARTTLS downgrade / stripping attack is possible', 'smtp2.azercell.com offers STARTTLS but allows MAIL FROM before TLS negotiation - STARTTLS downgrade / stripping attack is possible']}

- **EHLO/HELO:** {'hosts': [{'host': 'smtp1.azercell.com', 'ehlo': '250-smtp1.azercell.com Hello [37.114.152.173], pleased to meet you\r\n250-ENHANCEDSTATUSCODES\r\n250-PIPELINING\r\n250-8BITMIME\r\n250-SIZE 157286400\r\n250 STARTTLS', 'helo': '250 smtp1.azercell.com Hello [37.114.152.173], pleased to meet you', 'extensions': ['ENHANCEDSTATUSCODES', 'PIPELINING', '8BITMIME', 'SIZE 157286400', 'STARTTLS']}, {'host': 'smtp2.azercell.com', 'ehlo': '250-smtp2.azercell.com Hello [37.114.152.173], pleased to meet you\r\n250-ENHANCEDSTATUSCODES\r\n250-PIPELINING\r\n250-8BITMIME\r\n250-SIZE 157286400\r\n250 STARTTLS', 'helo': '250 smtp2.azercell.com Hello [37.114.152.173], pleased to meet you', 'extensions': ['ENHANCEDSTATUSCODES', 'PIPELINING', '8BITMIME', 'SIZE 157286400', 'STARTTLS']}], 'issues': ['HELO accepted on smtp1.azercell.com - legacy unauthenticated handshake still permitted', 'smtp1.azercell.com advertises potentially dangerous extensions via EHLO: PIPELINING', 'HELO accepted on smtp2.azercell.com - legacy unauthenticated handshake still permitted', 'smtp2.azercell.com advertises potentially dangerous extensions via EHLO: PIPELINING']}


### Exchange Findings

```json
[
  {
    "source": "hudsonrock_domain",
    "domain": "azercell.com",
    "total_stealers": 36717969,
    "total_employees": 4,
    "total_users": 100,
    "exposed_urls": [
      "https://wmail.azercell.com/owa/auth/logon.aspx",
      "https://ragw.azercell.com/+cscoe+/logon.html",
      "https://confluence.azercell.com/login.action",
      "https://wmail.azercell.com/owa/auth/expiredpassword.aspx",
      "https://www.azercell.com/my/login",
      "https://kabinetim.azercell.com/my/login",
      "https://www.azercell.com/selfservice/client",
      "http://www.azercell.com/selfservice/client",
      "https://www.azercell.com/chat/chat_widget.html",
      "https://www.azercell.com/selfservice/client/",
      "https://dealeronline.azercell.com/online/app/login",
      "https://kabinetim.azercell.com/my/password-change",
      "http://www.azercell.com/WebModule1/mainservlet",
      "https://support.azercell.com/servicedesk/customer/user/login",
      "http://www.azercell.com/selfservice/client/",
      "https://support.azercell.com/servicedesk/customer/user/visitportal",
      "http://dealeronline.azercell.com/online/app/login",
      "https://www.azercell.com",
      "https://kabinetim.azercell.com",
      "https://www.azercell.com/my/password-change",
      "https://www.azercell.com/WebModule1/mainservlet",
      "https://kc.azercell.com/auth/realms/dealer/protocol/openid-connect/auth",
      "https://mnpfd.azercell.com/MNPClient/login",
      "http://www.azercell.com/webmodule1/mainservlet",
      "http://www.azercell.com",
      "https://mnp-web.azercell.com/login",
      "https://kabinetim.azercell.com/my",
      "https://www.azercell.com/",
      "https://rhsso.azercell.com/auth/realms/external/login-actions/authenticate",
      "http://mnpfd.azercell.com/mnpclient/login",
      "https://kabinetim.azercell.com/login",
      "https://www.azercell.com/my/settings",
      "https://dealeronline.azercell.com",
      "https://support.azercell.com/servicedesk/customer/portal/1/user/login",
      "https://rhsso.azercell.com/auth/realms/dealer/protocol/openid-connect/auth",
      "http://www.azercell.com/",
      "https://support.azercell.com/servicedesk/customer/user/resetpassword",
      "https://kabinetim.azercell.com/my/login/sign-up/create-password",
      "http://www.azercell.com/az/",
      "https://www.azercell.com/webmodule1/mainservlet",
      "https://www.azercell.com/az/",
      "http://vmx.azercell.com/WebModule1/mainservlet",
      "http://mnpfd.azercell.com/MNPClient/login",
      "https://www.azercell.com/az",
      "https://www.azercell.com/my",
      "https://kc.azercell.com/auth/realms/external/login-actions/authenticate",
      "http://subscriber.azercell.com/index_main.jsp",
      "https://kc.azercell.com/auth/realms/external/protocol/openid-connect/auth",
      "https://support.azercell.com",
      "http://azercell.com/my/login",
      "https://biznes.azercell.com",
      "https://www.azercell.com/my/",
      "http://kids.azercell.com/login",
      "http://corporate.azercell.com/vcc/service.g",
      "http://www.azercell.com/az",
      "https://wifi-virtual.azercell.com",
      "http://dragon.azercell.com/",
      "http://intracell.azercell.com",
      "https://support.azercell.com/secure/Dashboard.jspa",
      "https://kabinetim.azercell.com/login/sign-up/create-password",
      "http://www.azercell.com/chat/chat_client.html",
      "https://keycloak.azercell.com/auth/realms/external/login-actions/authenticate",
      "https://www.azercell.com/chat/chat_client.html",
      "http://actioncontrol.azercell.com/login.aspx",
      "http://vcc.azercell.com/vcc/app/login",
      "http://dealeronline.azercell.com/",
      "https://icefaq.azercell.com/",
      "https://keycloak.azercell.com/auth/realms/external/protocol/openid-connect/auth",
      "https://etender.azercell.com",
      "https://fleet.azercell.com",
      "http://mms.azercell.com/index.jsp",
      "http://jiratestapp.azercell.com:8081/secure/Dashboard.jspa",
      "https://kc.azercell.com/auth/realms/dealer/login-actions/authenticate",
      "https://kabinetim.azercell.com/login/password-change/create-password",
      "http://vmx.azercell.com/webmodule1/mainservlet",
      "http://www1.azercell.com/",
      "http://www1.azercell.com/online/app/login",
      "https://kabinetim.azercell.com/",
      "https://mnpfd.azercell.com/mnpclient/login",
      "https://support.azercell.com/",
      "https://www.azercell.com/az/personal/tariffs/postpaid/hedsiz/",
      "https://support.azercell.com/servicedesk/customer/portal/1/user/resetpassword",
      "https://wifi-virtual.azercell.com/login.html",
      "http://jiratestapp.azercell.com:8080/secure/Dashboard.jspa",
      "http://jiratestapp.azercell.com:8080/secure/admin/user/AddUser!default.jspa",
      "https://support.azercell.com/secure/admin/user/UserBrowser.jspa",
      "https://support.azercell.com/secure/admin/dashboards/ViewSharedDashboards.jspa",
      "http://asf.azercell.com:5081/online/app/login",
      "http://asf.azercell.com:5083/online/app/login",
      "https://git.azercell.com/login",
      "https://support.azercell.com/login.jsp",
      "http://asf.azercell.com:5084/online/app/login",
      "https://asf.azercell.com:5084/online/app/login",
      "https://asf.azercell.com:5080/online/app/login",
      "https://kd.azercell.com",
      "https://asf.azercell.com:5081/online/app/login",
      "https://maven.azercell.com",
      "https://asf.azercell.com:5083/online/app/login",
      "https://dealeronline-new.azercell.com/online/app/login",
      "https://survey-new.azercell.com/login.aspx",
      "https://veriboard.azercell.com",
      "http://azercell.com",
      "http://azercell.com/WebModule1/mainservlet",
      "https://captive.azercell.com:8443/portal/PortalSetup.action"
    ],
    "severity": "critical"
  }
]
```


### Conventional / Guessed Emails

| Address                    | Status  | Confidence |
| -------------------------- | ------- | ---------- |
| admin@azercell.com         | guessed | 0.3        |
| administrator@azercell.com | guessed | 0.3        |
| support@azercell.com       | guessed | 0.3        |
| help@azercell.com          | guessed | 0.3        |
| info@azercell.com          | guessed | 0.3        |
| contact@azercell.com       | guessed | 0.3        |
| hello@azercell.com         | guessed | 0.3        |
| hi@azercell.com            | guessed | 0.3        |
| team@azercell.com          | guessed | 0.3        |
| mail@azercell.com          | guessed | 0.3        |
| email@azercell.com         | guessed | 0.3        |
| office@azercell.com        | guessed | 0.3        |
| hr@azercell.com            | guessed | 0.3        |
| jobs@azercell.com          | guessed | 0.3        |
| careers@azercell.com       | guessed | 0.3        |
| sales@azercell.com         | guessed | 0.3        |
| marketing@azercell.com     | guessed | 0.3        |
| billing@azercell.com       | guessed | 0.3        |
| accounts@azercell.com      | guessed | 0.3        |
| finance@azercell.com       | guessed | 0.3        |


### Social Recon

- **LinkedIn Found:** Yes

- **GitHub Found:** No


### Breach Data

**Total Breach Records: 321**


#### By Severity

| Severity   | Count |
| ---------- | ----- |
| 🔴 CRITICAL | 276   |
| 🟠 HIGH     | 45    |


#### Named Breaches

| Breach                      | Severity   | Affected | Data Classes |
| --------------------------- | ---------- | -------- | ------------ |
| Peopledatalabs.com          | 🔴 CRITICAL | 33       |              |
| LinkedIn.com                | 🔴 CRITICAL | 26       |              |
| 1.4BillionRecords           | 🟠 HIGH     | 9        | []           |
| VK.com                      | 🔴 CRITICAL | 9        |              |
| Badoo.com                   | 🔴 CRITICAL | 8        |              |
| Collection 1                | 🔴 CRITICAL | 7        |              |
| LinkedIn                    | 🟠 HIGH     | 7        | []           |
| Twitter.com (scraping data) | 🔴 CRITICAL | 7        |              |
| LinkedInScrape-2021         | 🟠 HIGH     | 6        | []           |
| PeopleDataLabs              | 🟠 HIGH     | 6        | []           |
| ExploitIN                   | 🟠 HIGH     | 5        | []           |
| Loveplanet.ru               | 🔴 CRITICAL | 5        |              |
| Collection-1                | 🟠 HIGH     | 4        | []           |
| AntiPublicCombo             | 🟠 HIGH     | 3        | []           |
| Apollo                      | 🔴 CRITICAL | 2        |              |
| MyFitnessPal.com            | 🔴 CRITICAL | 2        |              |
| VK                          | 🟠 HIGH     | 2        | []           |
| 123RF.com                   | 🔴 CRITICAL | 1        |              |
| AdultFriendFinder           | 🔴 CRITICAL | 1        |              |
| Bookmate.com                | 🔴 CRITICAL | 1        |              |
| Dailymotion.com             | 🔴 CRITICAL | 1        |              |
| Dropbox                     | 🟠 HIGH     | 1        | []           |
| GoNitro.com                 | 🔴 CRITICAL | 1        |              |
| HauteLook                   | 🟠 HIGH     | 1        | []           |
| Hautelook.com               | 🔴 CRITICAL | 1        |              |
| Jefit.com                   | 🔴 CRITICAL | 1        |              |
| Last.fm                     | 🔴 CRITICAL | 1        |              |
| Level.travel                | 🔴 CRITICAL | 1        |              |
| LiveJournal                 | 🔴 CRITICAL | 1        |              |
| MySpace.com                 | 🔴 CRITICAL | 1        |              |
| Silkroad                    | 🔴 CRITICAL | 1        |              |
| Sportmaster.ru              | 🔴 CRITICAL | 1        |              |
| Trello.com                  | 🔴 CRITICAL | 1        |              |
| Twitter-Scraped             | 🟠 HIGH     | 1        | []           |
| Whoosh.bike                 | 🔴 CRITICAL | 1        |              |
| Zynga.com                   | 🔴 CRITICAL | 1        |              |


#### Credential Leaks (up to 50)

| Email                    | Combo                                   | Date | Stealers |
| ------------------------ | --------------------------------------- | ---- | -------- |
| ali.ercan@azercell.com   | ali.ercan@azercell.com:4502137476       |      |          |
| 0504590981@azercell.com  | 0504590981@azercell.com:9045488         |      |          |
| azercell.com@gmail.com   | azercell.com@gmail.com:467664752466     |      |          |
| azercell.com@yandex.ru   | azercell.com@yandex.ru:467664752466     |      |          |
| a@azercell.com           | a@Azercell.com:123456                   |      |          |
| ayaz@azercell.com        | ayaz@azercell.com:3422                  |      |          |
| bmirzoyev@azercell.com   | bmirzoyev@azercell.com:2100028          |      |          |
| elchinm@azercell.com     | elchinm@azercell.com:051973             |      |          |
| eshemshir@azercell.com   | eshemshir@azercell.com:17ali91sham      |      |          |
| crrufat@azercell.com     | crrufat@azercell.com:3155470            |      |          |
| crsahile@azercell.com    | crsahile@azercell.com:515151            |      |          |
| cronigar@azercell.com    | cronigar@azercell.com:2118912           |      |          |
| cremil@azercell.com      | cremil@azercell.com:221039202210392     |      |          |
| crferid@azercell.com     | crferid@azercell.com:2055057a           |      |          |
| crferid@azercell.com     | crferid@azercell.com:6165242            |      |          |
| crchingiz@azercell.com   | crchingiz@azercell.com:19870503         |      |          |
| hrelshad@azercell.com    | hrelshad@azercell.com:123456            |      |          |
| hremin@azercell.com      | hremin@azercell.com:953488              |      |          |
| hrnarmina@azercell.com   | hrnarmina@azercell.com:050505           |      |          |
| ilham@azercell.com       | ilham@azercell.com:123456               |      |          |
| isnigar@azercell.com     | isnigar@azercell.com:654321             |      |          |
| ccvaleh@azercell.com     | ccvaleh@azercell.com:996712121          |      |          |
| cczsab@azercell.com      | cczsab@azercell.com:2100004Sz           |      |          |
| ccagunel@azercell.com    | ccagunel@azercell.com:832617607113421   |      |          |
| ccaxanim@azercell.com    | ccaxanim@azercell.com:337076431853845   |      |          |
| ccaytac@azercell.com     | ccaytac@azercell.com:391335259061795    |      |          |
| ccelnara@azercell.com    | ccelnara@azercell.com:184091269068795   |      |          |
| ccfahima@azercell.com    | ccfahima@azercell.com:322719199327432   |      |          |
| cckjoshgun@azercell.com  | cckjoshgun@azercell.com:105381008846387 |      |          |
| ccnaile@azercell.com     | ccnaile@azercell.com:19820807           |      |          |
| ccperviz@azercell.com    | ccperviz@azercell.com:6621033           |      |          |
| ccqilaha@azercell.com    | ccqilaha@azercell.com:208951278823909   |      |          |
| ccqorxan@azercell.com    | ccqorxan@azercell.com:666666            |      |          |
| ccriyad@azercell.com     | ccriyad@azercell.com:3206647            |      |          |
| ccrlet@azercell.com      | ccrlet@azercell.com:366995940864972     |      |          |
| ccsevinc@azercell.com    | ccsevinc@azercell.com:697392696563619   |      |          |
| ccteymur@azercell.com    | ccteymur@azercell.com:3142135           |      |          |
| marat@azercell.com       | Marat@azercell.com:375542702601136      |      |          |
| lazulfiya@azercell.com   | lazulfiya@azercell.com:123456789        |      |          |
| neliyev@azercell.com     | neliyev@azercell.com:22091984           |      |          |
| mibrahim@azercell.com    | mibrahim@azercell.com:01031964          |      |          |
| gapvefa@azercell.com     | gapvefa@azercell.com:123456             |      |          |
| sssamir@azercell.com     | sssamir@azercell.com:10lok1121          |      |          |
| ssgvugar@azercell.com    | ssgvugar@azercell.com:0R1j6sNm          |      |          |
| ssgvugar@azercell.com    | ssgvugar@azercell.com:2210441           |      |          |
| ssimran@azercell.com     | ssimran@azercell.com:191919ss           |      |          |
| ksada@azercell.com       | ksada@azercell.com:545919896991402      |      |          |
| laehmediyye@azercell.com | laehmediyye@azercell.com:3173705        |      |          |
| laemil@azercell.com      | laemil@azercell.com:6786641             |      |          |
| itnariman@azercell.com   | itnariman@azercell.com:373213           |      |          |


#### All Exposed Emails (76)

| Email                         |
| ----------------------------- |
| 0504590981@azercell.com       |
| a@azercell.com                |
| ali.ercan@azercell.com        |
| ayaz@azercell.com             |
| azercell.com@autorambler.ru   |
| azercell.com@bk.ru            |
| azercell.com@gmail.com        |
| azercell.com@inbox.ru         |
| azercell.com@lenta.ru         |
| azercell.com@list.ru          |
| azercell.com@mail.ru          |
| azercell.com@myrambler.ru     |
| azercell.com@nm.ru            |
| azercell.com@pochta.ru        |
| azercell.com@qip.ru           |
| azercell.com@rambler.ru       |
| azercell.com@ro.ru            |
| azercell.com@ya.ru            |
| azercell.com@ya.ua            |
| azercell.com@yandex.ru        |
| azercell.com@yandex.ua        |
| bmirzoyev@azercell.com        |
| ccagunel@azercell.com         |
| ccaxanim@azercell.com         |
| ccaytac@azercell.com          |
| ccelnara@azercell.com         |
| ccfahima@azercell.com         |
| cckjoshgun@azercell.com       |
| ccnaile@azercell.com          |
| ccperviz@azercell.com         |
| ccqilaha@azercell.com         |
| ccqorxan@azercell.com         |
| ccriyad@azercell.com          |
| ccrlet@azercell.com           |
| ccsevinc@azercell.com         |
| ccteymur@azercell.com         |
| ccvaleh@azercell.com          |
| cczsab@azercell.com           |
| crchingiz@azercell.com        |
| cremil@azercell.com           |
| crferid@azercell.com          |
| crkleyla@azercell.com         |
| cronigar@azercell.com         |
| crrufat@azercell.com          |
| crsahile@azercell.com         |
| elchinm@azercell.com          |
| eshemshir@azercell.com        |
| fnindira@azercell.com         |
| fnulker@azercell.com          |
| gapayten@azercell.com         |
| gapvefa@azercell.com          |
| hrelshad@azercell.com         |
| hremin@azercell.com           |
| hrnarmina@azercell.com        |
| ilham@azercell.com            |
| isnigar@azercell.com          |
| itkamil@azercell.com          |
| itkayan@azercell.com          |
| itnariman@azercell.com        |
| itramil@azercell.com          |
| ksada@azercell.com            |
| laehmediyye@azercell.com      |
| laemil@azercell.com           |
| lazulfiya@azercell.com        |
| marat@azercell.com            |
| mibrahim@azercell.com         |
| neliyev@azercell.com          |
| sevinj.teymurova@azercell.com |
| ssgvugar@azercell.com         |
| ssimran@azercell.com          |
| sssamir@azercell.com          |
| teadalat@azercell.com         |
| teehtiram@azercell.com        |
| tekonul@azercell.com          |
| teseymur@azercell.com         |
| teteymur@azercell.com         |


### Email Result Payload (azercell.com)

```json
{
  "harvest_recon": {
    "harvested_emails": [],
    "social_patterns": {
      "linkedin_found": true,
      "github_found": false,
      "patterns": []
    },
    "email_format_patterns": {
      "detected_patterns": [],
      "confidence": 0.0,
      "sample_count": 0
    },
    "conventional_emails": [
      {
        "address": "admin@azercell.com",
        "status": "guessed",
        "confidence": 0.3
      },
      {
        "address": "administrator@azercell.com",
        "status": "guessed",
        "confidence": 0.3
      },
      {
        "address": "support@azercell.com",
        "status": "guessed",
        "confidence": 0.3
      },
      {
        "address": "help@azercell.com",
        "status": "guessed",
        "confidence": 0.3
      },
      {
        "address": "info@azercell.com",
        "status": "guessed",
        "confidence": 0.3
      },
      {
        "address": "contact@azercell.com",
        "status": "guessed",
        "confidence": 0.3
      },
      {
        "address": "hello@azercell.com",
        "status": "guessed",
        "confidence": 0.3
      },
      {
        "address": "hi@azercell.com",
        "status": "guessed",
        "confidence": 0.3
      },
      {
        "address": "team@azercell.com",
        "status": "guessed",
        "confidence": 0.3
      },
      {
        "address": "mail@azercell.com",
        "status": "guessed",
        "confidence": 0.3
      },
      {
        "address": "email@azercell.com",
        "status": "guessed",
        "confidence": 0.3
      },
      {
        "address": "office@azercell.com",
        "status": "guessed",
        "confidence": 0.3
      },
      {
        "address": "hr@azercell.com",
        "status": "guessed",
        "confidence": 0.3
      },
      {
        "address": "jobs@azercell.com",
        "status": "guessed",
        "confidence": 0.3
      },
      {
        "address": "careers@azercell.com",
        "status": "guessed",
        "confidence": 0.3
      },
      {
        "address": "sales@azercell.com",
        "status": "guessed",
        "confidence": 0.3
      },
      {
        "address": "marketing@azercell.com",
        "status": "guessed",
        "confidence": 0.3
      },
      {
        "address": "billing@azercell.com",
        "status": "guessed",
        "confidence": 0.3
      },
      {
        "address": "accounts@azercell.com",
        "status": "guessed",
        "confidence": 0.3
      },
      {
        "address": "finance@azercell.com",
        "status": "guessed",
        "confidence": 0.3
      }
    ]
  },
  "dns_sec": {
    "mx_records": [
      {
        "priority": 5,
        "host": "smtp1.azercell.com",
        "ips": [
          "5.191.90.87"
        ]
      },
      {
        "priority": 15,
        "host": "smtp2.azercell.com",
        "ips": [
          "5.191.90.88"
        ]
      }
    ],
    "spf": {
      "record": "v=spf1 ip4:217.168.177.101 ip4:5.191.90.6 ip4:5.191.90.87 ip4:5.191.90.88 a mx a:mailgw.azercell.com a:mailgw-a.azercell.com a:smtp1.azercell.com a:smtp2.azercell.com mx:azercell.com include:spf.protection.outlook.com include:_spf.anpdm.com -all",
      "all_qualifier": "fail",
      "include_count": 2,
      "issues": []
    },
    "dkim": {
      "found_selectors": [
        "default",
        "s1",
        "s2"
      ],
      "issues": []
    },
    "dmarc": {
      "record": "v=DMARC1; p=none; rua=mailto:postmaster@azercell.com",
      "policy": "none",
      "subdomain_policy": "none",
      "pct": 100,
      "rua": [
        "mailto:postmaster@azercell.com"
      ],
      "ruf": [],
      "issues": [
        "DMARC policy is 'none' - monitoring only, no enforcement against spoofed mail"
      ]
    },
    "spoofing_risk": {
      "score": 40,
      "level": "MEDIUM"
    },
    "mta_sts": {
      "txt_record": null,
      "policy_file": null,
      "mode": null,
      "mx_covered": [],
      "max_age": null,
      "issues": [
        "No MTA-STS TXT record found - TLS downgrade attacks possible"
      ]
    },
    "dkim_key_strength": {
      "selectors": {
        "default": {
          "key_type": "rsa",
          "revoked": false,
          "key_bits": 1024,
          "strength": "weak"
        },
        "s1": {
          "key_type": "rsa",
          "revoked": false,
          "key_bits": 2048,
          "strength": "adequate"
        },
        "s2": {
          "key_type": "rsa",
          "revoked": false,
          "key_bits": 2048,
          "strength": "adequate"
        }
      },
      "issues": [
        "Selector 'default' uses 1024-bit RSA - below 2048-bit minimum"
      ]
    },
    "spf_lookup_depth": {
      "effective_lookup_count": 9,
      "limit": 10,
      "exceeded": false,
      "tree": {
        "a:azercell.com": {},
        "mx:azercell.com": {},
        "a:mailgw.azercell.com": {},
        "a:mailgw-a.azercell.com": {},
        "a:smtp1.azercell.com": {},
        "a:smtp2.azercell.com": {},
        "include:spf.protection.outlook.com": {},
        "include:_spf.anpdm.com": {}
      },
      "issues": []
    },
    "subdomain_takeover": {
      "mx_hosts": [
        {
          "host": "smtp1.azercell.com",
          "a_records": [
            "5.191.90.87"
          ],
          "smtp_reachable": true,
          "known_provider": null,
          "takeover_risk": "none"
        },
        {
          "host": "smtp2.azercell.com",
          "a_records": [
            "5.191.90.88"
          ],
          "smtp_reachable": true,
          "known_provider": null,
          "takeover_risk": "none"
        }
      ],
      "issues": []
    },
    "bimi": {
      "record": null,
      "logo_url": null,
      "vmc_url": null,
      "issues": [
        "No BIMI record found"
      ]
    },
    "caa": {
      "records": [],
      "issuers": [],
      "issue_wildcard": [],
      "iodef": [],
      "issues": [
        "No CAA records found - any CA can issue TLS certificates for this domain"
      ]
    },
    "null_mx": {
      "null_mx_present": false,
      "applicable": false,
      "issues": []
    },
    "dane": {
      "mx_dane": [
        {
          "host": "smtp1.azercell.com",
          "tlsa_name": "_25._tcp.smtp1.azercell.com",
          "records": [],
          "dane_enabled": false
        },
        {
          "host": "smtp2.azercell.com",
          "tlsa_name": "_25._tcp.smtp2.azercell.com",
          "records": [],
          "dane_enabled": false
        }
      ],
      "issues": [
        "No DANE/TLSA record for 'smtp1.azercell.com' - TLS certificate cannot be pinned via DNS",
        "No DANE/TLSA record for 'smtp2.azercell.com' - TLS certificate cannot be pinned via DNS"
      ]
    }
  },
  "provider_gateways": {
    "email_provider": {
      "name": "Self-hosted / Unknown",
      "confidence": 0.3,
      "mx_hosts": [
        "smtp1.azercell.com",
        "smtp2.azercell.com"
      ],
      "matched_signature": null
    },
    "mail_relays": [],
    "security_gateways": []
  },
  "breaches": {
    "findings": [
      {
        "source": "proxynova_domain",
        "email": "ali.ercan@azercell.com",
        "domain": "azercell.com",
        "combo_line": "ali.ercan@azercell.com:4502137476",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "0504590981@azercell.com",
        "domain": "azercell.com",
        "combo_line": "0504590981@azercell.com:9045488",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "azercell.com@gmail.com",
        "domain": "azercell.com",
        "combo_line": "azercell.com@gmail.com:467664752466",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "azercell.com@yandex.ru",
        "domain": "azercell.com",
        "combo_line": "azercell.com@yandex.ru:467664752466",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "a@azercell.com",
        "domain": "azercell.com",
        "combo_line": "a@Azercell.com:123456",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "ayaz@azercell.com",
        "domain": "azercell.com",
        "combo_line": "ayaz@azercell.com:3422",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "bmirzoyev@azercell.com",
        "domain": "azercell.com",
        "combo_line": "bmirzoyev@azercell.com:2100028",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "elchinm@azercell.com",
        "domain": "azercell.com",
        "combo_line": "elchinm@azercell.com:051973",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "eshemshir@azercell.com",
        "domain": "azercell.com",
        "combo_line": "eshemshir@azercell.com:17ali91sham",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "crrufat@azercell.com",
        "domain": "azercell.com",
        "combo_line": "crrufat@azercell.com:3155470",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "crsahile@azercell.com",
        "domain": "azercell.com",
        "combo_line": "crsahile@azercell.com:515151",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "cronigar@azercell.com",
        "domain": "azercell.com",
        "combo_line": "cronigar@azercell.com:2118912",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "cremil@azercell.com",
        "domain": "azercell.com",
        "combo_line": "cremil@azercell.com:221039202210392",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "crferid@azercell.com",
        "domain": "azercell.com",
        "combo_line": "crferid@azercell.com:2055057a",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "crferid@azercell.com",
        "domain": "azercell.com",
        "combo_line": "crferid@azercell.com:6165242",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "crchingiz@azercell.com",
        "domain": "azercell.com",
        "combo_line": "crchingiz@azercell.com:19870503",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "hrelshad@azercell.com",
        "domain": "azercell.com",
        "combo_line": "hrelshad@azercell.com:123456",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "hremin@azercell.com",
        "domain": "azercell.com",
        "combo_line": "hremin@azercell.com:953488",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "hrnarmina@azercell.com",
        "domain": "azercell.com",
        "combo_line": "hrnarmina@azercell.com:050505",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "ilham@azercell.com",
        "domain": "azercell.com",
        "combo_line": "ilham@azercell.com:123456",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "isnigar@azercell.com",
        "domain": "azercell.com",
        "combo_line": "isnigar@azercell.com:654321",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "ccvaleh@azercell.com",
        "domain": "azercell.com",
        "combo_line": "ccvaleh@azercell.com:996712121",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "cczsab@azercell.com",
        "domain": "azercell.com",
        "combo_line": "cczsab@azercell.com:2100004Sz",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "ccagunel@azercell.com",
        "domain": "azercell.com",
        "combo_line": "ccagunel@azercell.com:832617607113421",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "ccaxanim@azercell.com",
        "domain": "azercell.com",
        "combo_line": "ccaxanim@azercell.com:337076431853845",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "ccaytac@azercell.com",
        "domain": "azercell.com",
        "combo_line": "ccaytac@azercell.com:391335259061795",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "ccelnara@azercell.com",
        "domain": "azercell.com",
        "combo_line": "ccelnara@azercell.com:184091269068795",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "ccfahima@azercell.com",
        "domain": "azercell.com",
        "combo_line": "ccfahima@azercell.com:322719199327432",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "cckjoshgun@azercell.com",
        "domain": "azercell.com",
        "combo_line": "cckjoshgun@azercell.com:105381008846387",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "ccnaile@azercell.com",
        "domain": "azercell.com",
        "combo_line": "ccnaile@azercell.com:19820807",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "ccperviz@azercell.com",
        "domain": "azercell.com",
        "combo_line": "ccperviz@azercell.com:6621033",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "ccqilaha@azercell.com",
        "domain": "azercell.com",
        "combo_line": "ccqilaha@azercell.com:208951278823909",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "ccqorxan@azercell.com",
        "domain": "azercell.com",
        "combo_line": "ccqorxan@azercell.com:666666",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "ccriyad@azercell.com",
        "domain": "azercell.com",
        "combo_line": "ccriyad@azercell.com:3206647",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "ccrlet@azercell.com",
        "domain": "azercell.com",
        "combo_line": "ccrlet@azercell.com:366995940864972",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "ccsevinc@azercell.com",
        "domain": "azercell.com",
        "combo_line": "ccsevinc@azercell.com:697392696563619",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "ccteymur@azercell.com",
        "domain": "azercell.com",
        "combo_line": "ccteymur@azercell.com:3142135",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "marat@azercell.com",
        "domain": "azercell.com",
        "combo_line": "Marat@azercell.com:375542702601136",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "lazulfiya@azercell.com",
        "domain": "azercell.com",
        "combo_line": "lazulfiya@azercell.com:123456789",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "neliyev@azercell.com",
        "domain": "azercell.com",
        "combo_line": "neliyev@azercell.com:22091984",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "mibrahim@azercell.com",
        "domain": "azercell.com",
        "combo_line": "mibrahim@azercell.com:01031964",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "gapvefa@azercell.com",
        "domain": "azercell.com",
        "combo_line": "gapvefa@azercell.com:123456",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "sssamir@azercell.com",
        "domain": "azercell.com",
        "combo_line": "sssamir@azercell.com:10lok1121",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "ssgvugar@azercell.com",
        "domain": "azercell.com",
        "combo_line": "ssgvugar@azercell.com:0R1j6sNm",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "ssgvugar@azercell.com",
        "domain": "azercell.com",
        "combo_line": "ssgvugar@azercell.com:2210441",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "ssimran@azercell.com",
        "domain": "azercell.com",
        "combo_line": "ssimran@azercell.com:191919ss",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "ksada@azercell.com",
        "domain": "azercell.com",
        "combo_line": "ksada@azercell.com:545919896991402",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "laehmediyye@azercell.com",
        "domain": "azercell.com",
        "combo_line": "laehmediyye@azercell.com:3173705",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "laemil@azercell.com",
        "domain": "azercell.com",
        "combo_line": "laemil@azercell.com:6786641",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "itnariman@azercell.com",
        "domain": "azercell.com",
        "combo_line": "itnariman@azercell.com:373213",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "sevinj.teymurova@azercell.com",
        "domain": "azercell.com",
        "combo_line": "sevinj.teymurova@azercell.com:123456",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "teseymur@azercell.com",
        "domain": "azercell.com",
        "combo_line": "teseymur@azercell.com:2310093",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "teehtiram@azercell.com",
        "domain": "azercell.com",
        "combo_line": "teehtiram@azercell.com:(2009aydin)",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "teadalat@azercell.com",
        "domain": "azercell.com",
        "combo_line": "teadalat@azercell.com:72572500",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "tekonul@azercell.com",
        "domain": "azercell.com",
        "combo_line": "tekonul@azercell.com:846190558040909",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "teteymur@azercell.com",
        "domain": "azercell.com",
        "combo_line": "teteymur@azercell.com:814758797469766",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "crkleyla@azercell.com",
        "domain": "azercell.com",
        "combo_line": "crkleyla@azercell.com:$HEX[6c696c753a2a323231]",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "fnindira@azercell.com",
        "domain": "azercell.com",
        "combo_line": "fnindira@azercell.com:123qwe&#33:@",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "fnindira@azercell.com",
        "domain": "azercell.com",
        "combo_line": "fnindira@azercell.com:123qwe&#33;@",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "azercell.com@myrambler.ru",
        "domain": "azercell.com",
        "combo_line": "azercell.com@myrambler.ru:azercellcom",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "azercell.com@rambler.ru",
        "domain": "azercell.com",
        "combo_line": "azercell.com@rambler.ru:azercell.com",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "itkamil@azercell.com",
        "domain": "azercell.com",
        "combo_line": "itkamil@azercell.com:1d7e44612be40be1",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "itkayan@azercell.com",
        "domain": "azercell.com",
        "combo_line": "itkayan@azercell.com:397d839a5ba404a1",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "itramil@azercell.com",
        "domain": "azercell.com",
        "combo_line": "itramil@azercell.com:6e97bb044543d3ea",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "gapayten@azercell.com",
        "domain": "azercell.com",
        "combo_line": "gapayten@azercell.com:*4941DF7D88CFAD27188342870DB113CC031F3F54",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "fnindira@azercell.com",
        "domain": "azercell.com",
        "combo_line": "fnindira@azercell.com:12345",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "fnindira@azercell.com",
        "domain": "azercell.com",
        "combo_line": "fnindira@azercell.com:123qwe&",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "fnulker@azercell.com",
        "domain": "azercell.com",
        "combo_line": "fnulker@azercell.com:1f9ee7bc41e6c2a2",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "azercell.com@autorambler.ru",
        "domain": "azercell.com",
        "combo_line": "azercell.com@autorambler.ru:467664752466",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "azercell.com@bk.ru",
        "domain": "azercell.com",
        "combo_line": "azercell.com@bk.ru:467664752466",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "azercell.com@inbox.ru",
        "domain": "azercell.com",
        "combo_line": "azercell.com@inbox.ru:467664752466",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "azercell.com@lenta.ru",
        "domain": "azercell.com",
        "combo_line": "azercell.com@lenta.ru:467664752466",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "azercell.com@list.ru",
        "domain": "azercell.com",
        "combo_line": "azercell.com@list.ru:467664752466",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "azercell.com@mail.ru",
        "domain": "azercell.com",
        "combo_line": "azercell.com@mail.ru:467664752466",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "azercell.com@myrambler.ru",
        "domain": "azercell.com",
        "combo_line": "azercell.com@myrambler.ru:4676647524",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "azercell.com@myrambler.ru",
        "domain": "azercell.com",
        "combo_line": "azercell.com@myrambler.ru:46766475246",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "azercell.com@myrambler.ru",
        "domain": "azercell.com",
        "combo_line": "azercell.com@myrambler.ru:467664752466",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "azercell.com@nm.ru",
        "domain": "azercell.com",
        "combo_line": "azercell.com@nm.ru:467664752466",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "azercell.com@pochta.ru",
        "domain": "azercell.com",
        "combo_line": "azercell.com@pochta.ru:467664752466",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "azercell.com@qip.ru",
        "domain": "azercell.com",
        "combo_line": "azercell.com@qip.ru:467664752466",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "azercell.com@rambler.ru",
        "domain": "azercell.com",
        "combo_line": "azercell.com@rambler.ru:467664",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "azercell.com@rambler.ru",
        "domain": "azercell.com",
        "combo_line": "azercell.com@rambler.ru:467664732466",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "azercell.com@rambler.ru",
        "domain": "azercell.com",
        "combo_line": "azercell.com@rambler.ru:467664752466",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "azercell.com@ro.ru",
        "domain": "azercell.com",
        "combo_line": "azercell.com@ro.ru:467664752466",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "azercell.com@ya.ru",
        "domain": "azercell.com",
        "combo_line": "azercell.com@ya.ru:467664752466",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "azercell.com@ya.ua",
        "domain": "azercell.com",
        "combo_line": "azercell.com@ya.ua:467664752466",
        "severity": "critical"
      },
      {
        "source": "proxynova_domain",
        "email": "azercell.com@yandex.ua",
        "domain": "azercell.com",
        "combo_line": "azercell.com@yandex.ua:467664752466",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "0504590981@azercell.com",
        "combo_line": "0504590981@azercell.com:9045488",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "a@azercell.com",
        "combo_line": "a@Azercell.com:123456",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "hrnarmina@azercell.com",
        "combo_line": "hrnarmina@azercell.com:050505",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "ayaz@azercell.com",
        "combo_line": "ayaz@azercell.com:3422",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "ali.ercan@azercell.com",
        "combo_line": "ali.ercan@azercell.com:4502137476",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "azercell.com@gmail.com",
        "combo_line": "azercell.com@gmail.com:467664752466",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "azercell.com@yandex.ru",
        "combo_line": "azercell.com@yandex.ru:467664752466",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "bmirzoyev@azercell.com",
        "combo_line": "bmirzoyev@azercell.com:2100028",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "bmirzoyev@azercell.com",
        "combo_line": "bmirzoyev@azercell.com:nejifeke",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "ccagunel@azercell.com",
        "combo_line": "ccagunel@azercell.com:832617607113421",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "ccaxanim@azercell.com",
        "combo_line": "ccaxanim@azercell.com:337076431853845",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "ccaxanim@azercell.com",
        "combo_line": "ccaxanim@azercell.com:valida31",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "ccaytac@azercell.com",
        "combo_line": "ccaytac@azercell.com:391335259061795",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "ccelnara@azercell.com",
        "combo_line": "ccelnara@azercell.com:184091269068795",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "ccfahima@azercell.com",
        "combo_line": "ccfahima@azercell.com:322719199327432",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "cckjoshgun@azercell.com",
        "combo_line": "cckjoshgun@azercell.com:105381008846387",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "ccnaile@azercell.com",
        "combo_line": "ccnaile@azercell.com:19820807",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "ccnaile@azercell.com",
        "combo_line": "ccnaile@azercell.com:hecer",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "ccnaile@azercell.com",
        "combo_line": "ccnaile@azercell.com:naila1982",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "ccperviz@azercell.com",
        "combo_line": "ccperviz@azercell.com:6621033",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "ccqilaha@azercell.com",
        "combo_line": "ccqilaha@azercell.com:208951278823909",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "ccqorxan@azercell.com",
        "combo_line": "ccqorxan@azercell.com:666666",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "ccriyad@azercell.com",
        "combo_line": "ccriyad@azercell.com:3206647",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "ccrlet@azercell.com",
        "combo_line": "ccrlet@azercell.com:366995940864972",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "ccsevinc@azercell.com",
        "combo_line": "ccsevinc@azercell.com:697392696563619",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "ccteymur@azercell.com",
        "combo_line": "ccteymur@azercell.com:3142135",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "ccvaleh@azercell.com",
        "combo_line": "ccvaleh@azercell.com:996712121",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "cczsab@azercell.com",
        "combo_line": "cczsab@azercell.com:2100004Sz",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "crchingiz@azercell.com",
        "combo_line": "crchingiz@azercell.com:19870503",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "cremil@azercell.com",
        "combo_line": "cremil@azercell.com:221039202210392",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "crferid@azercell.com",
        "combo_line": "crferid@azercell.com:2055057a",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "crferid@azercell.com",
        "combo_line": "crferid@azercell.com:6165242",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "crferid@azercell.com",
        "combo_line": "crferid@azercell.com:zufusegy",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "crkleyla@azercell.com",
        "combo_line": "crkleyla@azercell.com:$HEX[6c696c753a2a323231]",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "cronigar@azercell.com",
        "combo_line": "cronigar@azercell.com:2118912",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "crrufat@azercell.com",
        "combo_line": "crrufat@azercell.com:3155470",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "crrufat@azercell.com",
        "combo_line": "crrufat@azercell.com:A3155470!",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "crsahile@azercell.com",
        "combo_line": "crsahile@azercell.com:515151",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "elchinm@azercell.com",
        "combo_line": "elchinm@azercell.com:051973",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "eshemshir@azercell.com",
        "combo_line": "eshemshir@azercell.com:17ali91sham",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "eshemshir@azercell.com",
        "combo_line": "eshemshir@azercell.com:celyziqi",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "fnindira@azercell.com",
        "combo_line": "fnindira@azercell.com:123qwe&#33:@",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "fnindira@azercell.com",
        "combo_line": "fnindira@azercell.com:123qwe&#33;@",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "fnulker@azercell.com",
        "combo_line": "fnulker@azercell.com:lir117",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "fnulker@azercell.com",
        "combo_line": "fnulker@azercell.com:witm117",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "gapvefa@azercell.com",
        "combo_line": "gapvefa@azercell.com:123456",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "hrelshad@azercell.com",
        "combo_line": "hrelshad@azercell.com:123456",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "hremin@azercell.com",
        "combo_line": "hremin@azercell.com:953488",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "hremin@azercell.com",
        "combo_line": "hremin@azercell.com:emin161",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "hremin@azercell.com",
        "combo_line": "hremin@azercell.com:hremin",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "ilham@azercell.com",
        "combo_line": "ilham@azercell.com:123456",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "isnigar@azercell.com",
        "combo_line": "isnigar@azercell.com:654321",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "itkamil@azercell.com",
        "combo_line": "itkamil@azercell.com:gonzibaddi",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "itkayan@azercell.com",
        "combo_line": "itkayan@azercell.com:kayan",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "itnariman@azercell.com",
        "combo_line": "itnariman@azercell.com:373213",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "itramil@azercell.com",
        "combo_line": "itramil@azercell.com:criminal30",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "ksada@azercell.com",
        "combo_line": "ksada@azercell.com:545919896991402",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "laehmediyye@azercell.com",
        "combo_line": "laehmediyye@azercell.com:3173705",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "laemil@azercell.com",
        "combo_line": "laemil@azercell.com:6786641",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "lazulfiya@azercell.com",
        "combo_line": "lazulfiya@azercell.com:123456789",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "marat@azercell.com",
        "combo_line": "Marat@azercell.com:375542702601136",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "mibrahim@azercell.com",
        "combo_line": "mibrahim@azercell.com:01031964",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "neliyev@azercell.com",
        "combo_line": "neliyev@azercell.com:22091984",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "sevinj.teymurova@azercell.com",
        "combo_line": "sevinj.teymurova@azercell.com:123456",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "ssgvugar@azercell.com",
        "combo_line": "ssgvugar@azercell.com:0R1j6sNm",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "ssgvugar@azercell.com",
        "combo_line": "ssgvugar@azercell.com:2210441",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "ssimran@azercell.com",
        "combo_line": "ssimran@azercell.com:191919ss",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "sssamir@azercell.com",
        "combo_line": "sssamir@azercell.com:10lok1121",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "teadalat@azercell.com",
        "combo_line": "teadalat@azercell.com:72572500",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "teehtiram@azercell.com",
        "combo_line": "teehtiram@azercell.com:(2009aydin)",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "tekonul@azercell.com",
        "combo_line": "tekonul@azercell.com:846190558040909",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "teseymur@azercell.com",
        "combo_line": "teseymur@azercell.com:2310093",
        "severity": "critical"
      },
      {
        "source": "proxynova",
        "email": "teteymur@azercell.com",
        "combo_line": "teteymur@azercell.com:814758797469766",
        "severity": "critical"
      },
      {
        "source": "xon_email",
        "email": "0504590981@azercell.com",
        "breach_name": "1.4BillionRecords",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "0504590981@azercell.com",
        "breach_name": "VK",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "0504590981@azercell.com",
        "breach_name": "Collection-1",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "0504590981@azercell.com",
        "breach_name": "ExploitIN",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "ali.ercan@azercell.com",
        "breach_name": "1.4BillionRecords",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "ali.ercan@azercell.com",
        "breach_name": "PeopleDataLabs",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "ali.ercan@azercell.com",
        "breach_name": "LinkedInScrape-2021",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "ali.ercan@azercell.com",
        "breach_name": "LinkedIn",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "a@azercell.com",
        "breach_name": "1.4BillionRecords",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "a@azercell.com",
        "breach_name": "LinkedIn",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "a@azercell.com",
        "breach_name": "ExploitIN",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "ayaz@azercell.com",
        "breach_name": "Collection-1",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "ayaz@azercell.com",
        "breach_name": "1.4BillionRecords",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "ayaz@azercell.com",
        "breach_name": "AntiPublicCombo",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "ayaz@azercell.com",
        "breach_name": "ExploitIN",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "leakcheck_email",
        "email": "0504590981@azercell.com",
        "breach_name": "VK.com",
        "breach_date": "2012-01",
        "exposed_fields": [
          "id",
          "password"
        ],
        "severity": "critical"
      },
      {
        "source": "xon_email",
        "email": "ccaxanim@azercell.com",
        "breach_name": "HauteLook",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "ccaxanim@azercell.com",
        "breach_name": "LinkedInScrape-2021",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "ccaxanim@azercell.com",
        "breach_name": "AntiPublicCombo",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "ccaxanim@azercell.com",
        "breach_name": "1.4BillionRecords",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "ccaxanim@azercell.com",
        "breach_name": "LinkedIn",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "ccaxanim@azercell.com",
        "breach_name": "ExploitIN",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "ccaxanim@azercell.com",
        "breach_name": "Collection-1",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "ccaxanim@azercell.com",
        "breach_name": "PeopleDataLabs",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "ccrlet@azercell.com",
        "breach_name": "Dropbox",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "ccrlet@azercell.com",
        "breach_name": "LinkedInScrape-2021",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "ccrlet@azercell.com",
        "breach_name": "1.4BillionRecords",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "ccrlet@azercell.com",
        "breach_name": "LinkedIn",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "ccrlet@azercell.com",
        "breach_name": "PeopleDataLabs",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "cronigar@azercell.com",
        "breach_name": "1.4BillionRecords",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "cronigar@azercell.com",
        "breach_name": "LinkedIn",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "cronigar@azercell.com",
        "breach_name": "PeopleDataLabs",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "cronigar@azercell.com",
        "breach_name": "LinkedInScrape-2021",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "hremin@azercell.com",
        "breach_name": "Twitter-Scraped",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "hremin@azercell.com",
        "breach_name": "ExploitIN",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "hremin@azercell.com",
        "breach_name": "AntiPublicCombo",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "hremin@azercell.com",
        "breach_name": "VK",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "hremin@azercell.com",
        "breach_name": "Collection-1",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "hremin@azercell.com",
        "breach_name": "1.4BillionRecords",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "laehmediyye@azercell.com",
        "breach_name": "LinkedInScrape-2021",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "laehmediyye@azercell.com",
        "breach_name": "LinkedIn",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "laehmediyye@azercell.com",
        "breach_name": "PeopleDataLabs",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "laehmediyye@azercell.com",
        "breach_name": "1.4BillionRecords",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "leakcheck_email",
        "email": "a@azercell.com",
        "breach_name": "LinkedIn.com",
        "breach_date": "2012-05",
        "exposed_fields": [
          "id",
          "password"
        ],
        "severity": "critical"
      },
      {
        "source": "xon_email",
        "email": "sssamir@azercell.com",
        "breach_name": "PeopleDataLabs",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "sssamir@azercell.com",
        "breach_name": "LinkedInScrape-2021",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "xon_email",
        "email": "sssamir@azercell.com",
        "breach_name": "LinkedIn",
        "breach_date": "",
        "pwn_count": 0,
        "data_classes": [],
        "severity": "high"
      },
      {
        "source": "leakcheck_email",
        "email": "ali.ercan@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "id",
          "password",
          "address",
          "name"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "azercell.com@rambler.ru",
        "breach_name": "Level.travel",
        "breach_date": "2022-12",
        "exposed_fields": [
          "id",
          "password",
          "username"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "azercell.com@rambler.ru",
        "breach_name": "Silkroad",
        "breach_date": "2011-11",
        "exposed_fields": [
          "id",
          "password",
          "username"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "bmirzoyev@azercell.com",
        "breach_name": "Collection 1",
        "breach_date": "2019-01",
        "exposed_fields": [
          "password",
          "id",
          "dob",
          "last_name",
          "first_name"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "bmirzoyev@azercell.com",
        "breach_name": "Badoo.com",
        "breach_date": "2013-07",
        "exposed_fields": [
          "password",
          "id",
          "dob",
          "last_name",
          "first_name"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccagunel@azercell.com",
        "breach_name": "LinkedIn.com",
        "breach_date": "2012-05",
        "exposed_fields": [
          "password",
          "id",
          "profile_name",
          "username"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccagunel@azercell.com",
        "breach_name": "Twitter.com (scraping data)",
        "breach_date": "2022-01",
        "exposed_fields": [
          "password",
          "id",
          "profile_name",
          "username"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccaxanim@azercell.com",
        "breach_name": "LinkedIn.com",
        "breach_date": "2012-05",
        "exposed_fields": [
          "password",
          "id",
          "country",
          "name",
          "address",
          "zip",
          "last_name",
          "first_name"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccaxanim@azercell.com",
        "breach_name": "Hautelook.com",
        "breach_date": "2018-08",
        "exposed_fields": [
          "password",
          "id",
          "country",
          "name",
          "address",
          "zip",
          "last_name",
          "first_name"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccaxanim@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "password",
          "id",
          "country",
          "name",
          "address",
          "zip",
          "last_name",
          "first_name"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccaytac@azercell.com",
        "breach_name": "LinkedIn.com",
        "breach_date": "2012-05",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address",
          "ip",
          "username"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccaytac@azercell.com",
        "breach_name": "GoNitro.com",
        "breach_date": "2020-08",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address",
          "ip",
          "username"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccaytac@azercell.com",
        "breach_name": "MyFitnessPal.com",
        "breach_date": "2018-02",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address",
          "ip",
          "username"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccaytac@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address",
          "ip",
          "username"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccelnara@azercell.com",
        "breach_name": "LinkedIn.com",
        "breach_date": "2012-05",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccelnara@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccfahima@azercell.com",
        "breach_name": "LinkedIn.com",
        "breach_date": "2012-05",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccfahima@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "cckjoshgun@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "id",
          "password",
          "address",
          "name"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "cckjoshgun@azercell.com",
        "breach_name": "LinkedIn.com",
        "breach_date": "2012-05",
        "exposed_fields": [
          "id",
          "password",
          "address",
          "name"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccnaile@azercell.com",
        "breach_name": "Last.fm",
        "breach_date": "2012-07",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address",
          "profile_name",
          "username"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccnaile@azercell.com",
        "breach_name": "LinkedIn.com",
        "breach_date": "2012-05",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address",
          "profile_name",
          "username"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccnaile@azercell.com",
        "breach_name": "Twitter.com (scraping data)",
        "breach_date": "2022-01",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address",
          "profile_name",
          "username"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccnaile@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address",
          "profile_name",
          "username"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccperviz@azercell.com",
        "breach_name": "Badoo.com",
        "breach_date": "2013-07",
        "exposed_fields": [
          "password",
          "id",
          "dob",
          "last_name",
          "first_name",
          "ip",
          "username"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccperviz@azercell.com",
        "breach_name": "Loveplanet.ru",
        "breach_date": "2014-11",
        "exposed_fields": [
          "password",
          "id",
          "dob",
          "last_name",
          "first_name",
          "ip",
          "username"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccperviz@azercell.com",
        "breach_name": "Jefit.com",
        "breach_date": "2020-05",
        "exposed_fields": [
          "password",
          "id",
          "dob",
          "last_name",
          "first_name",
          "ip",
          "username"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccqilaha@azercell.com",
        "breach_name": "LinkedIn.com",
        "breach_date": "2012-05",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccqilaha@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccriyad@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "id",
          "password",
          "address",
          "name"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccriyad@azercell.com",
        "breach_name": "LinkedIn.com",
        "breach_date": "2012-05",
        "exposed_fields": [
          "id",
          "password",
          "address",
          "name"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccrlet@azercell.com",
        "breach_name": "LinkedIn.com",
        "breach_date": "2012-05",
        "exposed_fields": [
          "address",
          "password",
          "name",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccrlet@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "address",
          "password",
          "name",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccsevinc@azercell.com",
        "breach_name": "LinkedIn.com",
        "breach_date": "2012-05",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccsevinc@azercell.com",
        "breach_name": "Trello.com",
        "breach_date": "2024-01",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccsevinc@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccteymur@azercell.com",
        "breach_name": "LinkedIn.com",
        "breach_date": "2012-05",
        "exposed_fields": [
          "name",
          "username",
          "address",
          "password",
          "profile_name",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccteymur@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "name",
          "username",
          "address",
          "password",
          "profile_name",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccteymur@azercell.com",
        "breach_name": "Twitter.com (scraping data)",
        "breach_date": "2022-01",
        "exposed_fields": [
          "name",
          "username",
          "address",
          "password",
          "profile_name",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccvaleh@azercell.com",
        "breach_name": "Loveplanet.ru",
        "breach_date": "2014-11",
        "exposed_fields": [
          "id",
          "password"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ccvaleh@azercell.com",
        "breach_name": "VK.com",
        "breach_date": "2012-01",
        "exposed_fields": [
          "id",
          "password"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "cczsab@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "id",
          "password",
          "address",
          "name"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "cczsab@azercell.com",
        "breach_name": "LinkedIn.com",
        "breach_date": "2012-05",
        "exposed_fields": [
          "id",
          "password",
          "address",
          "name"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "crchingiz@azercell.com",
        "breach_name": "AdultFriendFinder",
        "breach_date": "2016-10",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address",
          "username"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "crchingiz@azercell.com",
        "breach_name": "LinkedIn.com",
        "breach_date": "2012-05",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address",
          "username"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "crchingiz@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address",
          "username"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "cremil@azercell.com",
        "breach_name": "VK.com",
        "breach_date": "2012-01",
        "exposed_fields": [
          "password",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "crferid@azercell.com",
        "breach_name": "Badoo.com",
        "breach_date": "2013-07",
        "exposed_fields": [
          "first_name",
          "dob",
          "name",
          "address",
          "password",
          "last_name",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "crferid@azercell.com",
        "breach_name": "VK.com",
        "breach_date": "2012-01",
        "exposed_fields": [
          "first_name",
          "dob",
          "name",
          "address",
          "password",
          "last_name",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "crferid@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "first_name",
          "dob",
          "name",
          "address",
          "password",
          "last_name",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "crkleyla@azercell.com",
        "breach_name": "Whoosh.bike",
        "breach_date": "2022-11",
        "exposed_fields": [
          "id",
          "phone",
          "last_name",
          "first_name",
          "password",
          "dob"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "crkleyla@azercell.com",
        "breach_name": "Loveplanet.ru",
        "breach_date": "2014-11",
        "exposed_fields": [
          "id",
          "phone",
          "last_name",
          "first_name",
          "password",
          "dob"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "crkleyla@azercell.com",
        "breach_name": "Badoo.com",
        "breach_date": "2013-07",
        "exposed_fields": [
          "id",
          "phone",
          "last_name",
          "first_name",
          "password",
          "dob"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "cronigar@azercell.com",
        "breach_name": "LinkedIn.com",
        "breach_date": "2012-05",
        "exposed_fields": [
          "address",
          "password",
          "name",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "cronigar@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "address",
          "password",
          "name",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "crrufat@azercell.com",
        "breach_name": "Zynga.com",
        "breach_date": "2019-09",
        "exposed_fields": [
          "id",
          "password",
          "profile_name",
          "last_name",
          "username",
          "first_name",
          "dob"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "crrufat@azercell.com",
        "breach_name": "LiveJournal",
        "breach_date": "2017-01",
        "exposed_fields": [
          "id",
          "password",
          "profile_name",
          "last_name",
          "username",
          "first_name",
          "dob"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "crrufat@azercell.com",
        "breach_name": "Badoo.com",
        "breach_date": "2013-07",
        "exposed_fields": [
          "id",
          "password",
          "profile_name",
          "last_name",
          "username",
          "first_name",
          "dob"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "crrufat@azercell.com",
        "breach_name": "Dailymotion.com",
        "breach_date": "2016-10",
        "exposed_fields": [
          "id",
          "password",
          "profile_name",
          "last_name",
          "username",
          "first_name",
          "dob"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "crrufat@azercell.com",
        "breach_name": "MySpace.com",
        "breach_date": "2008-07",
        "exposed_fields": [
          "id",
          "password",
          "profile_name",
          "last_name",
          "username",
          "first_name",
          "dob"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "crrufat@azercell.com",
        "breach_name": "Twitter.com (scraping data)",
        "breach_date": "2022-01",
        "exposed_fields": [
          "id",
          "password",
          "profile_name",
          "last_name",
          "username",
          "first_name",
          "dob"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "crsahile@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "address",
          "password",
          "name",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "elchinm@azercell.com",
        "breach_name": "LinkedIn.com",
        "breach_date": "2012-05",
        "exposed_fields": [
          "password",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "eshemshir@azercell.com",
        "breach_name": "LinkedIn.com",
        "breach_date": "2012-05",
        "exposed_fields": [
          "name",
          "id",
          "password",
          "profile_name",
          "last_name",
          "username",
          "first_name",
          "address",
          "dob"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "eshemshir@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "name",
          "id",
          "password",
          "profile_name",
          "last_name",
          "username",
          "first_name",
          "address",
          "dob"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "eshemshir@azercell.com",
        "breach_name": "Badoo.com",
        "breach_date": "2013-07",
        "exposed_fields": [
          "name",
          "id",
          "password",
          "profile_name",
          "last_name",
          "username",
          "first_name",
          "address",
          "dob"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "eshemshir@azercell.com",
        "breach_name": "Twitter.com (scraping data)",
        "breach_date": "2022-01",
        "exposed_fields": [
          "name",
          "id",
          "password",
          "profile_name",
          "last_name",
          "username",
          "first_name",
          "address",
          "dob"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "fnindira@azercell.com",
        "breach_name": "VK.com",
        "breach_date": "2012-01",
        "exposed_fields": [
          "id",
          "password"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "fnulker@azercell.com",
        "breach_name": "Collection 1",
        "breach_date": "2019-01",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "fnulker@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "gapvefa@azercell.com",
        "breach_name": "VK.com",
        "breach_date": "2012-01",
        "exposed_fields": [
          "username",
          "ip",
          "password",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "gapvefa@azercell.com",
        "breach_name": "MyFitnessPal.com",
        "breach_date": "2018-02",
        "exposed_fields": [
          "username",
          "ip",
          "password",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "hrelshad@azercell.com",
        "breach_name": "Loveplanet.ru",
        "breach_date": "2014-11",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address",
          "profile_name",
          "username"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "hrelshad@azercell.com",
        "breach_name": "Twitter.com (scraping data)",
        "breach_date": "2022-01",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address",
          "profile_name",
          "username"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "hrelshad@azercell.com",
        "breach_name": "123RF.com",
        "breach_date": "2020-02",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address",
          "profile_name",
          "username"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "hrelshad@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address",
          "profile_name",
          "username"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "hremin@azercell.com",
        "breach_name": "VK.com",
        "breach_date": "2012-01",
        "exposed_fields": [
          "username",
          "password",
          "profile_name",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "hremin@azercell.com",
        "breach_name": "Twitter.com (scraping data)",
        "breach_date": "2022-01",
        "exposed_fields": [
          "username",
          "password",
          "profile_name",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "hrnarmina@azercell.com",
        "breach_name": "VK.com",
        "breach_date": "2012-01",
        "exposed_fields": [
          "address",
          "password",
          "name",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "hrnarmina@azercell.com",
        "breach_name": "Collection 1",
        "breach_date": "2019-01",
        "exposed_fields": [
          "address",
          "password",
          "name",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "hrnarmina@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "address",
          "password",
          "name",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ilham@azercell.com",
        "breach_name": "Apollo",
        "breach_date": "2018-07",
        "exposed_fields": [
          "name",
          "country",
          "address",
          "password",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ilham@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "name",
          "country",
          "address",
          "password",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "isnigar@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "address",
          "password",
          "name",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "itkamil@azercell.com",
        "breach_name": "Collection 1",
        "breach_date": "2019-01",
        "exposed_fields": [
          "id",
          "password"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "itkayan@azercell.com",
        "breach_name": "Collection 1",
        "breach_date": "2019-01",
        "exposed_fields": [
          "password",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "itnariman@azercell.com",
        "breach_name": "LinkedIn.com",
        "breach_date": "2012-05",
        "exposed_fields": [
          "address",
          "password",
          "name",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "itnariman@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "address",
          "password",
          "name",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "itramil@azercell.com",
        "breach_name": "Collection 1",
        "breach_date": "2019-01",
        "exposed_fields": [
          "password",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ksada@azercell.com",
        "breach_name": "Bookmate.com",
        "breach_date": "2018-07",
        "exposed_fields": [
          "name",
          "username",
          "address",
          "password",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ksada@azercell.com",
        "breach_name": "LinkedIn.com",
        "breach_date": "2012-05",
        "exposed_fields": [
          "name",
          "username",
          "address",
          "password",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ksada@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "name",
          "username",
          "address",
          "password",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "laehmediyye@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "laemil@azercell.com",
        "breach_name": "Collection 1",
        "breach_date": "2019-01",
        "exposed_fields": [
          "password",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "lazulfiya@azercell.com",
        "breach_name": "Badoo.com",
        "breach_date": "2013-07",
        "exposed_fields": [
          "id",
          "last_name",
          "first_name",
          "password",
          "dob"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "marat@azercell.com",
        "breach_name": "Apollo",
        "breach_date": "2018-07",
        "exposed_fields": [
          "country",
          "id",
          "password",
          "name"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "marat@azercell.com",
        "breach_name": "LinkedIn.com",
        "breach_date": "2012-05",
        "exposed_fields": [
          "country",
          "id",
          "password",
          "name"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "mibrahim@azercell.com",
        "breach_name": "LinkedIn.com",
        "breach_date": "2012-05",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "mibrahim@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "neliyev@azercell.com",
        "breach_name": "Badoo.com",
        "breach_date": "2013-07",
        "exposed_fields": [
          "id",
          "password",
          "dob",
          "first_name"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "sevinj.teymurova@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "id",
          "password",
          "address",
          "name"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ssgvugar@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "id",
          "address",
          "name",
          "username",
          "password"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ssgvugar@azercell.com",
        "breach_name": "Loveplanet.ru",
        "breach_date": "2014-11",
        "exposed_fields": [
          "id",
          "address",
          "name",
          "username",
          "password"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ssgvugar@azercell.com",
        "breach_name": "VK.com",
        "breach_date": "2012-01",
        "exposed_fields": [
          "id",
          "address",
          "name",
          "username",
          "password"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ssimran@azercell.com",
        "breach_name": "Sportmaster.ru",
        "breach_date": "2023-01",
        "exposed_fields": [
          "id",
          "address",
          "phone",
          "name",
          "password",
          "city"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "ssimran@azercell.com",
        "breach_name": "LinkedIn.com",
        "breach_date": "2012-05",
        "exposed_fields": [
          "id",
          "address",
          "phone",
          "name",
          "password",
          "city"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "sssamir@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "teadalat@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "tekonul@azercell.com",
        "breach_name": "LinkedIn.com",
        "breach_date": "2012-05",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "tekonul@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "password",
          "id",
          "name",
          "address"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "teseymur@azercell.com",
        "breach_name": "LinkedIn.com",
        "breach_date": "2012-05",
        "exposed_fields": [
          "address",
          "password",
          "name",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "teseymur@azercell.com",
        "breach_name": "Peopledatalabs.com",
        "breach_date": "2015-01",
        "exposed_fields": [
          "address",
          "password",
          "name",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "leakcheck_email",
        "email": "teteymur@azercell.com",
        "breach_name": "LinkedIn.com",
        "breach_date": "2012-05",
        "exposed_fields": [
          "password",
          "id"
        ],
        "severity": "critical"
      },
      {
        "source": "hudsonrock_domain",
        "domain": "azercell.com",
        "total_stealers": 36717969,
        "total_employees": 4,
        "total_users": 100,
        "exposed_urls": [
          "https://wmail.azercell.com/owa/auth/logon.aspx",
          "https://ragw.azercell.com/+cscoe+/logon.html",
          "https://confluence.azercell.com/login.action",
          "https://wmail.azercell.com/owa/auth/expiredpassword.aspx",
          "https://www.azercell.com/my/login",
          "https://kabinetim.azercell.com/my/login",
          "https://www.azercell.com/selfservice/client",
          "http://www.azercell.com/selfservice/client",
          "https://www.azercell.com/chat/chat_widget.html",
          "https://www.azercell.com/selfservice/client/",
          "https://dealeronline.azercell.com/online/app/login",
          "https://kabinetim.azercell.com/my/password-change",
          "http://www.azercell.com/WebModule1/mainservlet",
          "https://support.azercell.com/servicedesk/customer/user/login",
          "http://www.azercell.com/selfservice/client/",
          "https://support.azercell.com/servicedesk/customer/user/visitportal",
          "http://dealeronline.azercell.com/online/app/login",
          "https://www.azercell.com",
          "https://kabinetim.azercell.com",
          "https://www.azercell.com/my/password-change",
          "https://www.azercell.com/WebModule1/mainservlet",
          "https://kc.azercell.com/auth/realms/dealer/protocol/openid-connect/auth",
          "https://mnpfd.azercell.com/MNPClient/login",
          "http://www.azercell.com/webmodule1/mainservlet",
          "http://www.azercell.com",
          "https://mnp-web.azercell.com/login",
          "https://kabinetim.azercell.com/my",
          "https://www.azercell.com/",
          "https://rhsso.azercell.com/auth/realms/external/login-actions/authenticate",
          "http://mnpfd.azercell.com/mnpclient/login",
          "https://kabinetim.azercell.com/login",
          "https://www.azercell.com/my/settings",
          "https://dealeronline.azercell.com",
          "https://support.azercell.com/servicedesk/customer/portal/1/user/login",
          "https://rhsso.azercell.com/auth/realms/dealer/protocol/openid-connect/auth",
          "http://www.azercell.com/",
          "https://support.azercell.com/servicedesk/customer/user/resetpassword",
          "https://kabinetim.azercell.com/my/login/sign-up/create-password",
          "http://www.azercell.com/az/",
          "https://www.azercell.com/webmodule1/mainservlet",
          "https://www.azercell.com/az/",
          "http://vmx.azercell.com/WebModule1/mainservlet",
          "http://mnpfd.azercell.com/MNPClient/login",
          "https://www.azercell.com/az",
          "https://www.azercell.com/my",
          "https://kc.azercell.com/auth/realms/external/login-actions/authenticate",
          "http://subscriber.azercell.com/index_main.jsp",
          "https://kc.azercell.com/auth/realms/external/protocol/openid-connect/auth",
          "https://support.azercell.com",
          "http://azercell.com/my/login",
          "https://biznes.azercell.com",
          "https://www.azercell.com/my/",
          "http://kids.azercell.com/login",
          "http://corporate.azercell.com/vcc/service.g",
          "http://www.azercell.com/az",
          "https://wifi-virtual.azercell.com",
          "http://dragon.azercell.com/",
          "http://intracell.azercell.com",
          "https://support.azercell.com/secure/Dashboard.jspa",
          "https://kabinetim.azercell.com/login/sign-up/create-password",
          "http://www.azercell.com/chat/chat_client.html",
          "https://keycloak.azercell.com/auth/realms/external/login-actions/authenticate",
          "https://www.azercell.com/chat/chat_client.html",
          "http://actioncontrol.azercell.com/login.aspx",
          "http://vcc.azercell.com/vcc/app/login",
          "http://dealeronline.azercell.com/",
          "https://icefaq.azercell.com/",
          "https://keycloak.azercell.com/auth/realms/external/protocol/openid-connect/auth",
          "https://etender.azercell.com",
          "https://fleet.azercell.com",
          "http://mms.azercell.com/index.jsp",
          "http://jiratestapp.azercell.com:8081/secure/Dashboard.jspa",
          "https://kc.azercell.com/auth/realms/dealer/login-actions/authenticate",
          "https://kabinetim.azercell.com/login/password-change/create-password",
          "http://vmx.azercell.com/webmodule1/mainservlet",
          "http://www1.azercell.com/",
          "http://www1.azercell.com/online/app/login",
          "https://kabinetim.azercell.com/",
          "https://mnpfd.azercell.com/mnpclient/login",
          "https://support.azercell.com/",
          "https://www.azercell.com/az/personal/tariffs/postpaid/hedsiz/",
          "https://support.azercell.com/servicedesk/customer/portal/1/user/resetpassword",
          "https://wifi-virtual.azercell.com/login.html",
          "http://jiratestapp.azercell.com:8080/secure/Dashboard.jspa",
          "http://jiratestapp.azercell.com:8080/secure/admin/user/AddUser!default.jspa",
          "https://support.azercell.com/secure/admin/user/UserBrowser.jspa",
          "https://support.azercell.com/secure/admin/dashboards/ViewSharedDashboards.jspa",
          "http://asf.azercell.com:5081/online/app/login",
          "http://asf.azercell.com:5083/online/app/login",
          "https://git.azercell.com/login",
          "https://support.azercell.com/login.jsp",
          "http://asf.azercell.com:5084/online/app/login",
          "https://asf.azercell.com:5084/online/app/login",
          "https://asf.azercell.com:5080/online/app/login",
          "https://kd.azercell.com",
          "https://asf.azercell.com:5081/online/app/login",
          "https://maven.azercell.com",
          "https://asf.azercell.com:5083/online/app/login",
          "https://dealeronline-new.azercell.com/online/app/login",
          "https://survey-new.azercell.com/login.aspx",
          "https://veriboard.azercell.com",
          "http://azercell.com",
          "http://azercell.com/WebModule1/mainservlet",
          "https://captive.azercell.com:8443/portal/PortalSetup.action"
        ],
        "severity": "critical"
      }
    ]
  },
  "service_config": {
    "port_scan": {
      "hosts": [
        {
          "host": "smtp1.azercell.com",
          "ports": [
            {
              "port": 25,
              "label": "SMTP",
              "protocol": "SMTP",
              "tls": false,
              "open": true,
              "banner": "220 smtp1.azercell.com ESMTP Thu,  8 Oct 2026 14:44:37 +0400",
              "starttls": true,
              "error": null
            },
            {
              "port": 465,
              "label": "SMTPS",
              "protocol": "SMTPS",
              "tls": true,
              "open": false,
              "banner": null,
              "starttls": null,
              "error": ""
            },
            {
              "port": 587,
              "label": "SMTP Submission",
              "protocol": "SMTP",
              "tls": false,
              "open": false,
              "banner": null,
              "starttls": null,
              "error": ""
            },
            {
              "port": 2525,
              "label": "SMTP Alt",
              "protocol": "SMTP",
              "tls": false,
              "open": false,
              "banner": null,
              "starttls": null,
              "error": ""
            },
            {
              "port": 143,
              "label": "IMAP",
              "protocol": "IMAP",
              "tls": false,
              "open": false,
              "banner": null,
              "starttls": null,
              "error": ""
            },
            {
              "port": 993,
              "label": "IMAPS",
              "protocol": "IMAPS",
              "tls": true,
              "open": false,
              "banner": null,
              "starttls": null,
              "error": ""
            },
            {
              "port": 110,
              "label": "POP3",
              "protocol": "POP3",
              "tls": false,
              "open": false,
              "banner": null,
              "starttls": null,
              "error": ""
            },
            {
              "port": 995,
              "label": "POP3S",
              "protocol": "POP3S",
              "tls": true,
              "open": false,
              "banner": null,
              "starttls": null,
              "error": ""
            },
            {
              "port": 4190,
              "label": "ManageSieve",
              "protocol": "SIEVE",
              "tls": false,
              "open": false,
              "banner": null,
              "starttls": null,
              "error": ""
            }
          ]
        },
        {
          "host": "smtp2.azercell.com",
          "ports": [
            {
              "port": 25,
              "label": "SMTP",
              "protocol": "SMTP",
              "tls": false,
              "open": true,
              "banner": "220 smtp2.azercell.com ESMTP Thu,  8 Oct 2026 14:44:41 +0400",
              "starttls": true,
              "error": null
            },
            {
              "port": 465,
              "label": "SMTPS",
              "protocol": "SMTPS",
              "tls": true,
              "open": false,
              "banner": null,
              "starttls": null,
              "error": ""
            },
            {
              "port": 587,
              "label": "SMTP Submission",
              "protocol": "SMTP",
              "tls": false,
              "open": false,
              "banner": null,
              "starttls": null,
              "error": ""
            },
            {
              "port": 2525,
              "label": "SMTP Alt",
              "protocol": "SMTP",
              "tls": false,
              "open": false,
              "banner": null,
              "starttls": null,
              "error": ""
            },
            {
              "port": 143,
              "label": "IMAP",
              "protocol": "IMAP",
              "tls": false,
              "open": false,
              "banner": null,
              "starttls": null,
              "error": ""
            },
            {
              "port": 993,
              "label": "IMAPS",
              "protocol": "IMAPS",
              "tls": true,
              "open": false,
              "banner": null,
              "starttls": null,
              "error": ""
            },
            {
              "port": 110,
              "label": "POP3",
              "protocol": "POP3",
              "tls": false,
              "open": false,
              "banner": null,
              "starttls": null,
              "error": ""
            },
            {
              "port": 995,
              "label": "POP3S",
              "protocol": "POP3S",
              "tls": true,
              "open": false,
              "banner": null,
              "starttls": null,
              "error": ""
            },
            {
              "port": 4190,
              "label": "ManageSieve",
              "protocol": "SIEVE",
              "tls": false,
              "open": false,
              "banner": null,
              "starttls": null,
              "error": ""
            }
          ]
        }
      ],
      "issues": []
    },
    "smtp_enum": {
      "hosts": [
        {
          "host": "smtp1.azercell.com",
          "connected": true,
          "error": null,
          "commands": [
            {
              "cmd": "VRFY root",
              "key": "VRFY root",
              "response": "252 2.5.2 Cannot VRFY user; try RCPT to attempt delivery",
              "code": "252"
            },
            {
              "cmd": "VRFY admin",
              "key": "VRFY admin",
              "response": "252 2.5.2 Cannot VRFY user; try RCPT to attempt delivery",
              "code": "252"
            },
            {
              "cmd": "EXPN root",
              "key": "EXPN root",
              "response": "500 5.5.1 Command unrecognized: \"EXPN root\"",
              "code": "500"
            },
            {
              "cmd": "EXPN all",
              "key": "EXPN all",
              "response": "500 5.5.1 Command unrecognized: \"EXPN all\"",
              "code": "500"
            },
            {
              "cmd": "RCPT TO:<root@localhost>",
              "key": "RCPT TO root@localhost",
              "response": "250 2.1.5 Recipient ok",
              "code": "250"
            },
            {
              "cmd": "RCPT TO:<admin@localhost>",
              "key": "RCPT TO admin@localhost",
              "response": "250 2.1.5 Recipient ok",
              "code": "250"
            }
          ],
          "vrfy_enabled": false,
          "expn_enabled": false
        },
        {
          "host": "smtp2.azercell.com",
          "connected": true,
          "error": null,
          "commands": [
            {
              "cmd": "VRFY root",
              "key": "VRFY root",
              "response": "252 2.5.2 Cannot VRFY user; try RCPT to attempt delivery",
              "code": "252"
            },
            {
              "cmd": "VRFY admin",
              "key": "VRFY admin",
              "response": "252 2.5.2 Cannot VRFY user; try RCPT to attempt delivery",
              "code": "252"
            },
            {
              "cmd": "EXPN root",
              "key": "EXPN root",
              "response": "500 5.5.1 Command unrecognized: \"EXPN root\"",
              "code": "500"
            },
            {
              "cmd": "EXPN all",
              "key": "EXPN all",
              "response": "500 5.5.1 Command unrecognized: \"EXPN all\"",
              "code": "500"
            },
            {
              "cmd": "RCPT TO:<root@localhost>",
              "key": "RCPT TO root@localhost",
              "response": "250 2.1.5 Recipient ok",
              "code": "250"
            },
            {
              "cmd": "RCPT TO:<admin@localhost>",
              "key": "RCPT TO admin@localhost",
              "response": "250 2.1.5 Recipient ok",
              "code": "250"
            }
          ],
          "vrfy_enabled": false,
          "expn_enabled": false
        }
      ],
      "issues": []
    },
    "autodiscover": {
      "available": true,
      "urls": [
        {
          "url": "https://azercell.com/autodiscover/autodiscover.json",
          "status": 200
        }
      ],
      "issues": []
    },
    "autoconfig": {
      "available": true,
      "url": "https://azercell.com/.well-known/autoconfig/mail/config-v1.1.xml",
      "issues": []
    },
    "catch_all": {
      "enabled": true,
      "probe_address": "oxsium-probe-no-such-user-xqz9@azercell.com",
      "tested_host": "smtp1.azercell.com",
      "issues": [
        "Catch-all is enabled on smtp1.azercell.com - accepts mail for any address, increases spam exposure and makes email harvesting easier"
      ]
    },
    "ehlo_helo": {
      "hosts": [
        {
          "host": "smtp1.azercell.com",
          "ehlo": "250-smtp1.azercell.com Hello [37.114.152.173], pleased to meet you\r\n250-ENHANCEDSTATUSCODES\r\n250-PIPELINING\r\n250-8BITMIME\r\n250-SIZE 157286400\r\n250 STARTTLS",
          "helo": "250 smtp1.azercell.com Hello [37.114.152.173], pleased to meet you",
          "extensions": [
            "ENHANCEDSTATUSCODES",
            "PIPELINING",
            "8BITMIME",
            "SIZE 157286400",
            "STARTTLS"
          ]
        },
        {
          "host": "smtp2.azercell.com",
          "ehlo": "250-smtp2.azercell.com Hello [37.114.152.173], pleased to meet you\r\n250-ENHANCEDSTATUSCODES\r\n250-PIPELINING\r\n250-8BITMIME\r\n250-SIZE 157286400\r\n250 STARTTLS",
          "helo": "250 smtp2.azercell.com Hello [37.114.152.173], pleased to meet you",
          "extensions": [
            "ENHANCEDSTATUSCODES",
            "PIPELINING",
            "8BITMIME",
            "SIZE 157286400",
            "STARTTLS"
          ]
        }
      ],
      "issues": [
        "HELO accepted on smtp1.azercell.com - legacy unauthenticated handshake still permitted",
        "smtp1.azercell.com advertises potentially dangerous extensions via EHLO: PIPELINING",
        "HELO accepted on smtp2.azercell.com - legacy unauthenticated handshake still permitted",
        "smtp2.azercell.com advertises potentially dangerous extensions via EHLO: PIPELINING"
      ]
    },
    "auth_mechanisms": {
      "hosts": [
        {
          "host": "smtp1.azercell.com",
          "advertised": [],
          "plain_text_allowed": false,
          "anonymous_allowed": false
        },
        {
          "host": "smtp2.azercell.com",
          "advertised": [],
          "plain_text_allowed": false,
          "anonymous_allowed": false
        }
      ],
      "issues": []
    },
    "open_relay": {
      "hosts": [
        {
          "host": "smtp1.azercell.com",
          "open_relay": false,
          "relay_response": "550 5.7.1 Relaying denied"
        },
        {
          "host": "smtp2.azercell.com",
          "open_relay": false,
          "relay_response": "550 5.7.1 Relaying denied"
        }
      ],
      "issues": []
    },
    "starttls_downgrade": {
      "hosts": [
        {
          "host": "smtp1.azercell.com",
          "starttls_offered": true,
          "downgrade_possible": true,
          "plain_data_accepted": true
        },
        {
          "host": "smtp2.azercell.com",
          "starttls_offered": true,
          "downgrade_possible": true,
          "plain_data_accepted": true
        }
      ],
      "issues": [
        "smtp1.azercell.com offers STARTTLS but allows MAIL FROM before TLS negotiation - STARTTLS downgrade / stripping attack is possible",
        "smtp2.azercell.com offers STARTTLS but allows MAIL FROM before TLS negotiation - STARTTLS downgrade / stripping attack is possible"
      ]
    }
  },
  "exchange": {
    "findings": [
      {
        "source": "hudsonrock_domain",
        "domain": "azercell.com",
        "total_stealers": 36717969,
        "total_employees": 4,
        "total_users": 100,
        "exposed_urls": [
          "https://wmail.azercell.com/owa/auth/logon.aspx",
          "https://ragw.azercell.com/+cscoe+/logon.html",
          "https://confluence.azercell.com/login.action",
          "https://wmail.azercell.com/owa/auth/expiredpassword.aspx",
          "https://www.azercell.com/my/login",
          "https://kabinetim.azercell.com/my/login",
          "https://www.azercell.com/selfservice/client",
          "http://www.azercell.com/selfservice/client",
          "https://www.azercell.com/chat/chat_widget.html",
          "https://www.azercell.com/selfservice/client/",
          "https://dealeronline.azercell.com/online/app/login",
          "https://kabinetim.azercell.com/my/password-change",
          "http://www.azercell.com/WebModule1/mainservlet",
          "https://support.azercell.com/servicedesk/customer/user/login",
          "http://www.azercell.com/selfservice/client/",
          "https://support.azercell.com/servicedesk/customer/user/visitportal",
          "http://dealeronline.azercell.com/online/app/login",
          "https://www.azercell.com",
          "https://kabinetim.azercell.com",
          "https://www.azercell.com/my/password-change",
          "https://www.azercell.com/WebModule1/mainservlet",
          "https://kc.azercell.com/auth/realms/dealer/protocol/openid-connect/auth",
          "https://mnpfd.azercell.com/MNPClient/login",
          "http://www.azercell.com/webmodule1/mainservlet",
          "http://www.azercell.com",
          "https://mnp-web.azercell.com/login",
          "https://kabinetim.azercell.com/my",
          "https://www.azercell.com/",
          "https://rhsso.azercell.com/auth/realms/external/login-actions/authenticate",
          "http://mnpfd.azercell.com/mnpclient/login",
          "https://kabinetim.azercell.com/login",
          "https://www.azercell.com/my/settings",
          "https://dealeronline.azercell.com",
          "https://support.azercell.com/servicedesk/customer/portal/1/user/login",
          "https://rhsso.azercell.com/auth/realms/dealer/protocol/openid-connect/auth",
          "http://www.azercell.com/",
          "https://support.azercell.com/servicedesk/customer/user/resetpassword",
          "https://kabinetim.azercell.com/my/login/sign-up/create-password",
          "http://www.azercell.com/az/",
          "https://www.azercell.com/webmodule1/mainservlet",
          "https://www.azercell.com/az/",
          "http://vmx.azercell.com/WebModule1/mainservlet",
          "http://mnpfd.azercell.com/MNPClient/login",
          "https://www.azercell.com/az",
          "https://www.azercell.com/my",
          "https://kc.azercell.com/auth/realms/external/login-actions/authenticate",
          "http://subscriber.azercell.com/index_main.jsp",
          "https://kc.azercell.com/auth/realms/external/protocol/openid-connect/auth",
          "https://support.azercell.com",
          "http://azercell.com/my/login",
          "https://biznes.azercell.com",
          "https://www.azercell.com/my/",
          "http://kids.azercell.com/login",
          "http://corporate.azercell.com/vcc/service.g",
          "http://www.azercell.com/az",
          "https://wifi-virtual.azercell.com",
          "http://dragon.azercell.com/",
          "http://intracell.azercell.com",
          "https://support.azercell.com/secure/Dashboard.jspa",
          "https://kabinetim.azercell.com/login/sign-up/create-password",
          "http://www.azercell.com/chat/chat_client.html",
          "https://keycloak.azercell.com/auth/realms/external/login-actions/authenticate",
          "https://www.azercell.com/chat/chat_client.html",
          "http://actioncontrol.azercell.com/login.aspx",
          "http://vcc.azercell.com/vcc/app/login",
          "http://dealeronline.azercell.com/",
          "https://icefaq.azercell.com/",
          "https://keycloak.azercell.com/auth/realms/external/protocol/openid-connect/auth",
          "https://etender.azercell.com",
          "https://fleet.azercell.com",
          "http://mms.azercell.com/index.jsp",
          "http://jiratestapp.azercell.com:8081/secure/Dashboard.jspa",
          "https://kc.azercell.com/auth/realms/dealer/login-actions/authenticate",
          "https://kabinetim.azercell.com/login/password-change/create-password",
          "http://vmx.azercell.com/webmodule1/mainservlet",
          "http://www1.azercell.com/",
          "http://www1.azercell.com/online/app/login",
          "https://kabinetim.azercell.com/",
          "https://mnpfd.azercell.com/mnpclient/login",
          "https://support.azercell.com/",
          "https://www.azercell.com/az/personal/tariffs/postpaid/hedsiz/",
          "https://support.azercell.com/servicedesk/customer/portal/1/user/resetpassword",
          "https://wifi-virtual.azercell.com/login.html",
          "http://jiratestapp.azercell.com:8080/secure/Dashboard.jspa",
          "http://jiratestapp.azercell.com:8080/secure/admin/user/AddUser!default.jspa",
          "https://support.azercell.com/secure/admin/user/UserBrowser.jspa",
          "https://support.azercell.com/secure/admin/dashboards/ViewSharedDashboards.jspa",
          "http://asf.azercell.com:5081/online/app/login",
          "http://asf.azercell.com:5083/online/app/login",
          "https://git.azercell.com/login",
          "https://support.azercell.com/login.jsp",
          "http://asf.azercell.com:5084/online/app/login",
          "https://asf.azercell.com:5084/online/app/login",
          "https://asf.azercell.com:5080/online/app/login",
          "https://kd.azercell.com",
          "https://asf.azercell.com:5081/online/app/login",
          "https://maven.azercell.com",
          "https://asf.azercell.com:5083/online/app/login",
          "https://dealeronline-new.azercell.com/online/app/login",
          "https://survey-new.azercell.com/login.aspx",
          "https://veriboard.azercell.com",
          "http://azercell.com",
          "http://azercell.com/WebModule1/mainservlet",
          "https://captive.azercell.com:8443/portal/PortalSetup.action"
        ],
        "severity": "critical"
      }
    ]
  },
  "ntlm": {
    "findings": [
      {
        "source": "auth_endpoint",
        "url": "https://wmail.azercell.com/rpc/rpcproxy.dll",
        "path": "/rpc/rpcproxy.dll",
        "http_status": 401,
        "auth_required": true,
        "auth_type": "Basic",
        "www_authenticate": "Basic realm=\"wmail.azercell.com\"",
        "disclosures": {
          "X-OWA-Version": "15.2.2562.17",
          "WWW-Authenticate": "Basic realm=\"wmail.azercell.com\"",
          "Set-Cookie": "TS0160ab2a=01db3e592ea1baa346452fb3cb26c53bdc7726b70a7b35812d258a4cb9e27f5e7d18e65ccec0ac0414b0c2c557bf7121a01b2f0343; Path=/; Domain=.wmail.azercell.com"
        },
        "severity": "high",
        "version_info": {
          "label": "Exchange SE RTM",
          "build": "15.2.2562.17",
          "release_date": "2025-07-08",
          "kb": "KB5047155",
          "is_latest": false,
          "versions_behind": 10,
          "days_old": 457,
          "cve_count": 38,
          "cves": [
            {
              "id": "CVE-2026-55008",
              "title": "Exchange Spoofing — XSS CRITICAL (Jul 2026)",
              "cvss": 9.6,
              "severity": "critical",
              "type": "Spoofing / XSS",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "XSS allowing unauthenticated spoofing with critical CVSS score of 9.6. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55008"
              ]
            },
            {
              "id": "CVE-2026-69356",
              "title": "Exchange Spoofing — Sender Impersonation (Sep 2026)",
              "cvss": 9.3,
              "severity": "critical",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Allows an attacker to impersonate a different sender in Exchange emails. CVSS 9.3. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69356"
              ]
            },
            {
              "id": "CVE-2026-69641",
              "title": "Exchange EoP — High Severity (Sep 2026)",
              "cvss": 9.1,
              "severity": "critical",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Permits attackers to obtain elevated privileges within Exchange. CVSS 9.1. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69641"
              ]
            },
            {
              "id": "CVE-2025-59249",
              "title": "Exchange EoP — Weak Authentication (Oct 2025)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Weak authentication mechanism enabling privilege escalation. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59249"
              ]
            },
            {
              "id": "CVE-2026-69355",
              "title": "Exchange RCE — Authenticated (Sep 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Authenticated attacker can execute arbitrary code on the Exchange server. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69355"
              ]
            },
            {
              "id": "CVE-2026-62913",
              "title": "Exchange RCE — Heap Buffer Overflow (Aug 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Heap buffer overflow permitting authenticated remote code execution. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62913"
              ]
            },
            {
              "id": "CVE-2026-55005",
              "title": "Exchange RCE — Heap Buffer Overflow (Jul 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Heap-based buffer overflow enabling authenticated remote code execution. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55005"
              ]
            },
            {
              "id": "CVE-2026-45504",
              "title": "Exchange EoP — SSRF (Jun 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "SSRF vulnerability enabling authenticated privilege escalation. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45504"
              ]
            },
            {
              "id": "CVE-2025-53782",
              "title": "Exchange EoP — Authentication Algorithm (Oct 2025)",
              "cvss": 8.4,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Incorrect implementation of authentication algorithm allowing an unauthorized attacker to elevate privileges locally. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53782"
              ]
            },
            {
              "id": "CVE-2026-69380",
              "title": "Exchange EoP — Missing Authorization (Sep 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Missing authorization flaw enabling low-privilege users to read and send mail as other Exchange users. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69380"
              ]
            },
            {
              "id": "CVE-2026-55007",
              "title": "Exchange RCE (Jul/Sep 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Remote code execution vulnerability. Partially addressed in July 2026 SU and fully patched in September 2026 SU. Does not affect Exchange 2016.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55007"
              ]
            },
            {
              "id": "CVE-2026-42897",
              "title": "Exchange XSS / Information Disclosure — Exploited (Jun 2026)",
              "cvss": 8.1,
              "severity": "critical",
              "type": "Information Disclosure / XSS",
              "auth_required": false,
              "exploited_in_wild": true,
              "description": "XSS flaw permitting unauthenticated remote spoofing and information disclosure. Exploited in the wild before patch release. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42897"
              ]
            },
            {
              "id": "CVE-2026-47631",
              "title": "Exchange Spoofing — Input Sanitization (Jun 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Input sanitization flaw enabling unauthenticated spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-47631"
              ]
            },
            {
              "id": "CVE-2026-45503",
              "title": "Exchange Information Disclosure — Authorization Flaw (Jun 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Authorization flaw exposing sensitive Exchange information. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45503"
              ]
            },
            {
              "id": "CVE-2026-62911",
              "title": "Exchange EoP — Replay Authentication Bypass (Aug 2026)",
              "cvss": 8.0,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Replay-based authentication bypass letting an authenticated attacker escalate privileges. Nearly 22,000 exposed servers identified as vulnerable. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62911"
              ]
            },
            {
              "id": "CVE-2026-55009",
              "title": "Exchange EoP — Unsafe Deserialization (Jul/Aug 2026)",
              "cvss": 7.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Unsafe deserialization enabling local privilege elevation. Disclosed July 2026, fully fixed in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55009"
              ]
            },
            {
              "id": "CVE-2026-55006",
              "title": "Exchange EoP — Access Controls (Jul 2026)",
              "cvss": 7.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Overly coarse access controls enabling privilege escalation. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55006"
              ]
            },
            {
              "id": "CVE-2025-33051",
              "title": "Exchange Information Disclosure (Aug 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Exposure of sensitive Exchange information to an unauthorized actor. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33051"
              ]
            },
            {
              "id": "CVE-2025-59248",
              "title": "Exchange Spoofing (Oct 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Input validation flaw permitting unauthorized spoofing. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59248"
              ]
            },
            {
              "id": "CVE-2025-64666",
              "title": "Exchange EoP — Input Validation (Dec 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Improper input validation allowing an authorized attacker to elevate privileges. Patched in December 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64666"
              ]
            },
            {
              "id": "CVE-2026-69378",
              "title": "Exchange DoS (Sep 2026)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Denial of Service",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Allows an attacker to crash the Exchange service. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69378"
              ]
            },
            {
              "id": "CVE-2026-45583",
              "title": "Exchange RCE — Code Injection (Jun 2026)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Code injection flaw permitting unauthenticated remote code execution. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45583"
              ]
            },
            {
              "id": "CVE-2026-62914",
              "title": "Exchange Spoofing — XSS (Aug 2026)",
              "cvss": 7.3,
              "severity": "high",
              "type": "Spoofing / XSS",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Cross-site scripting enabling content spoofing by authenticated users. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62914"
              ]
            },
            {
              "id": "CVE-2026-62910",
              "title": "Exchange EoP — Resource Injection CRITICAL (Aug 2026)",
              "cvss": 7.2,
              "severity": "critical",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Resource injection enabling privilege escalation. Classified critical despite CVSS 7.2 due to attack surface. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62910"
              ]
            },
            {
              "id": "CVE-2025-25005",
              "title": "Exchange Tampering (Aug 2025)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Tampering",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Input validation flaw allowing an authenticated attacker to tamper with Exchange data. Patched in August 2025 SU (first SE SU1, CU15 SU0).",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25005"
              ]
            },
            {
              "id": "CVE-2026-21527",
              "title": "Exchange Spoofing (Feb 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "UI misrepresentation enabling user spoofing by authenticated attackers. Patched in February 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-21527"
              ]
            },
            {
              "id": "CVE-2026-69361",
              "title": "Exchange Spoofing — SSRF (Sep 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Server-side request forgery issue enabling spoofing over the network. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69361"
              ]
            },
            {
              "id": "CVE-2026-69375",
              "title": "Exchange Tampering (Sep 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Tampering",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Enables unauthorized data manipulation in Exchange. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69375"
              ]
            },
            {
              "id": "CVE-2026-65813",
              "title": "Exchange EoP — SSRF (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Server-side request forgery flaw letting an authenticated attacker gain higher privileges remotely. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-65813"
              ]
            },
            {
              "id": "CVE-2026-62915",
              "title": "Exchange Security Feature Bypass (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Security Feature Bypass",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Authorization bypass allowing logged-in users to sidestep Exchange security controls. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62915"
              ]
            },
            {
              "id": "CVE-2026-62912",
              "title": "Exchange DoS — Unsafe Deserialization (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Denial of Service",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Unsafe deserialization allowing service crashes. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62912"
              ]
            },
            {
              "id": "CVE-2026-45501",
              "title": "Exchange Spoofing — SSRF (Jun 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "SSRF vulnerability allowing content spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45501"
              ]
            },
            {
              "id": "CVE-2026-45500",
              "title": "Exchange Spoofing — Output Encoding (Jun 2026)",
              "cvss": 6.1,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Output encoding flaw enabling unauthenticated spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45500"
              ]
            },
            {
              "id": "CVE-2026-69382",
              "title": "Exchange Information Disclosure (Sep 2026)",
              "cvss": 5.9,
              "severity": "medium",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Permits disclosure of restricted Exchange information. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69382"
              ]
            },
            {
              "id": "CVE-2025-25006",
              "title": "Exchange Spoofing (Aug 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Special element handling flaw enabling spoofing of Exchange content. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25006"
              ]
            },
            {
              "id": "CVE-2025-25007",
              "title": "Exchange Spoofing (Aug 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Input validation flaw permitting unauthorized spoofing of Exchange email content. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25007"
              ]
            },
            {
              "id": "CVE-2025-64667",
              "title": "Exchange Spoofing — UI Misrepresentation (Dec 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "UI misrepresentation enabling spoofing of Exchange content. Patched in December 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64667"
              ]
            },
            {
              "id": "CVE-2026-45502",
              "title": "Exchange Information Disclosure — SSRF (Jun 2026)",
              "cvss": 5.0,
              "severity": "medium",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Lower-severity SSRF enabling information leakage from Exchange. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45502"
              ]
            }
          ]
        }
      },
      {
        "source": "mapi_connect",
        "url": "https://azercell.com/mapi/emsmdb/",
        "path": "/mapi/emsmdb/",
        "http_status": 200,
        "disclosures": {},
        "severity": "low"
      },
      {
        "source": "owa_fingerprint",
        "url": "https://wmail.azercell.com/sites/",
        "path": "/sites/",
        "http_status": 404,
        "disclosures": {
          "Set-Cookie": "TS0160ab2a=01db3e592e9a30146293f4751f7fbc684504db243fa74e33b4328eda6bba34a4a8ff66cd60b6e3fd07bfa0ffdeac3edaa9337a9512; Path=/; Domain=.wmail.azercell.com"
        },
        "severity": "low",
        "version_info": {}
      },
      {
        "source": "autodiscover_xml",
        "url": "https://azercell.com/autodiscover/autodiscover.xml",
        "path": "/autodiscover/autodiscover.xml",
        "http_status": 302,
        "disclosures": {
          "Set-Cookie": "evo1xcukdl=3knlg586qpe54ts2fslufmns7l; path=/; secure; HttpOnly"
        },
        "severity": "low"
      },
      {
        "source": "auth_endpoint",
        "url": "https://wmail.azercell.com/PowerShell/",
        "path": "/PowerShell/",
        "http_status": 401,
        "auth_required": true,
        "auth_type": "Kerberos",
        "www_authenticate": "Kerberos",
        "disclosures": {
          "X-OWA-Version": "15.2.2562.17",
          "X-FEServer": "MBX19-N01",
          "WWW-Authenticate": "Kerberos",
          "Set-Cookie": "TS0160ab2a=01db3e592e257589538dbebacb99a7f358fe46c12313213e4ce1ccb3d7d21148ef8ba739a51a0deb9c1056f8ac1552b65c71645391; Path=/; Domain=.wmail.azercell.com"
        },
        "severity": "high",
        "version_info": {
          "label": "Exchange SE RTM",
          "build": "15.2.2562.17",
          "release_date": "2025-07-08",
          "kb": "KB5047155",
          "is_latest": false,
          "versions_behind": 10,
          "days_old": 457,
          "cve_count": 38,
          "cves": [
            {
              "id": "CVE-2026-55008",
              "title": "Exchange Spoofing — XSS CRITICAL (Jul 2026)",
              "cvss": 9.6,
              "severity": "critical",
              "type": "Spoofing / XSS",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "XSS allowing unauthenticated spoofing with critical CVSS score of 9.6. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55008"
              ]
            },
            {
              "id": "CVE-2026-69356",
              "title": "Exchange Spoofing — Sender Impersonation (Sep 2026)",
              "cvss": 9.3,
              "severity": "critical",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Allows an attacker to impersonate a different sender in Exchange emails. CVSS 9.3. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69356"
              ]
            },
            {
              "id": "CVE-2026-69641",
              "title": "Exchange EoP — High Severity (Sep 2026)",
              "cvss": 9.1,
              "severity": "critical",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Permits attackers to obtain elevated privileges within Exchange. CVSS 9.1. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69641"
              ]
            },
            {
              "id": "CVE-2025-59249",
              "title": "Exchange EoP — Weak Authentication (Oct 2025)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Weak authentication mechanism enabling privilege escalation. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59249"
              ]
            },
            {
              "id": "CVE-2026-69355",
              "title": "Exchange RCE — Authenticated (Sep 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Authenticated attacker can execute arbitrary code on the Exchange server. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69355"
              ]
            },
            {
              "id": "CVE-2026-62913",
              "title": "Exchange RCE — Heap Buffer Overflow (Aug 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Heap buffer overflow permitting authenticated remote code execution. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62913"
              ]
            },
            {
              "id": "CVE-2026-55005",
              "title": "Exchange RCE — Heap Buffer Overflow (Jul 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Heap-based buffer overflow enabling authenticated remote code execution. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55005"
              ]
            },
            {
              "id": "CVE-2026-45504",
              "title": "Exchange EoP — SSRF (Jun 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "SSRF vulnerability enabling authenticated privilege escalation. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45504"
              ]
            },
            {
              "id": "CVE-2025-53782",
              "title": "Exchange EoP — Authentication Algorithm (Oct 2025)",
              "cvss": 8.4,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Incorrect implementation of authentication algorithm allowing an unauthorized attacker to elevate privileges locally. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53782"
              ]
            },
            {
              "id": "CVE-2026-69380",
              "title": "Exchange EoP — Missing Authorization (Sep 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Missing authorization flaw enabling low-privilege users to read and send mail as other Exchange users. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69380"
              ]
            },
            {
              "id": "CVE-2026-55007",
              "title": "Exchange RCE (Jul/Sep 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Remote code execution vulnerability. Partially addressed in July 2026 SU and fully patched in September 2026 SU. Does not affect Exchange 2016.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55007"
              ]
            },
            {
              "id": "CVE-2026-42897",
              "title": "Exchange XSS / Information Disclosure — Exploited (Jun 2026)",
              "cvss": 8.1,
              "severity": "critical",
              "type": "Information Disclosure / XSS",
              "auth_required": false,
              "exploited_in_wild": true,
              "description": "XSS flaw permitting unauthenticated remote spoofing and information disclosure. Exploited in the wild before patch release. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42897"
              ]
            },
            {
              "id": "CVE-2026-47631",
              "title": "Exchange Spoofing — Input Sanitization (Jun 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Input sanitization flaw enabling unauthenticated spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-47631"
              ]
            },
            {
              "id": "CVE-2026-45503",
              "title": "Exchange Information Disclosure — Authorization Flaw (Jun 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Authorization flaw exposing sensitive Exchange information. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45503"
              ]
            },
            {
              "id": "CVE-2026-62911",
              "title": "Exchange EoP — Replay Authentication Bypass (Aug 2026)",
              "cvss": 8.0,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Replay-based authentication bypass letting an authenticated attacker escalate privileges. Nearly 22,000 exposed servers identified as vulnerable. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62911"
              ]
            },
            {
              "id": "CVE-2026-55009",
              "title": "Exchange EoP — Unsafe Deserialization (Jul/Aug 2026)",
              "cvss": 7.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Unsafe deserialization enabling local privilege elevation. Disclosed July 2026, fully fixed in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55009"
              ]
            },
            {
              "id": "CVE-2026-55006",
              "title": "Exchange EoP — Access Controls (Jul 2026)",
              "cvss": 7.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Overly coarse access controls enabling privilege escalation. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55006"
              ]
            },
            {
              "id": "CVE-2025-33051",
              "title": "Exchange Information Disclosure (Aug 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Exposure of sensitive Exchange information to an unauthorized actor. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33051"
              ]
            },
            {
              "id": "CVE-2025-59248",
              "title": "Exchange Spoofing (Oct 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Input validation flaw permitting unauthorized spoofing. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59248"
              ]
            },
            {
              "id": "CVE-2025-64666",
              "title": "Exchange EoP — Input Validation (Dec 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Improper input validation allowing an authorized attacker to elevate privileges. Patched in December 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64666"
              ]
            },
            {
              "id": "CVE-2026-69378",
              "title": "Exchange DoS (Sep 2026)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Denial of Service",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Allows an attacker to crash the Exchange service. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69378"
              ]
            },
            {
              "id": "CVE-2026-45583",
              "title": "Exchange RCE — Code Injection (Jun 2026)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Code injection flaw permitting unauthenticated remote code execution. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45583"
              ]
            },
            {
              "id": "CVE-2026-62914",
              "title": "Exchange Spoofing — XSS (Aug 2026)",
              "cvss": 7.3,
              "severity": "high",
              "type": "Spoofing / XSS",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Cross-site scripting enabling content spoofing by authenticated users. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62914"
              ]
            },
            {
              "id": "CVE-2026-62910",
              "title": "Exchange EoP — Resource Injection CRITICAL (Aug 2026)",
              "cvss": 7.2,
              "severity": "critical",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Resource injection enabling privilege escalation. Classified critical despite CVSS 7.2 due to attack surface. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62910"
              ]
            },
            {
              "id": "CVE-2025-25005",
              "title": "Exchange Tampering (Aug 2025)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Tampering",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Input validation flaw allowing an authenticated attacker to tamper with Exchange data. Patched in August 2025 SU (first SE SU1, CU15 SU0).",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25005"
              ]
            },
            {
              "id": "CVE-2026-21527",
              "title": "Exchange Spoofing (Feb 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "UI misrepresentation enabling user spoofing by authenticated attackers. Patched in February 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-21527"
              ]
            },
            {
              "id": "CVE-2026-69361",
              "title": "Exchange Spoofing — SSRF (Sep 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Server-side request forgery issue enabling spoofing over the network. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69361"
              ]
            },
            {
              "id": "CVE-2026-69375",
              "title": "Exchange Tampering (Sep 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Tampering",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Enables unauthorized data manipulation in Exchange. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69375"
              ]
            },
            {
              "id": "CVE-2026-65813",
              "title": "Exchange EoP — SSRF (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Server-side request forgery flaw letting an authenticated attacker gain higher privileges remotely. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-65813"
              ]
            },
            {
              "id": "CVE-2026-62915",
              "title": "Exchange Security Feature Bypass (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Security Feature Bypass",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Authorization bypass allowing logged-in users to sidestep Exchange security controls. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62915"
              ]
            },
            {
              "id": "CVE-2026-62912",
              "title": "Exchange DoS — Unsafe Deserialization (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Denial of Service",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Unsafe deserialization allowing service crashes. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62912"
              ]
            },
            {
              "id": "CVE-2026-45501",
              "title": "Exchange Spoofing — SSRF (Jun 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "SSRF vulnerability allowing content spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45501"
              ]
            },
            {
              "id": "CVE-2026-45500",
              "title": "Exchange Spoofing — Output Encoding (Jun 2026)",
              "cvss": 6.1,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Output encoding flaw enabling unauthenticated spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45500"
              ]
            },
            {
              "id": "CVE-2026-69382",
              "title": "Exchange Information Disclosure (Sep 2026)",
              "cvss": 5.9,
              "severity": "medium",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Permits disclosure of restricted Exchange information. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69382"
              ]
            },
            {
              "id": "CVE-2025-25006",
              "title": "Exchange Spoofing (Aug 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Special element handling flaw enabling spoofing of Exchange content. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25006"
              ]
            },
            {
              "id": "CVE-2025-25007",
              "title": "Exchange Spoofing (Aug 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Input validation flaw permitting unauthorized spoofing of Exchange email content. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25007"
              ]
            },
            {
              "id": "CVE-2025-64667",
              "title": "Exchange Spoofing — UI Misrepresentation (Dec 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "UI misrepresentation enabling spoofing of Exchange content. Patched in December 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64667"
              ]
            },
            {
              "id": "CVE-2026-45502",
              "title": "Exchange Information Disclosure — SSRF (Jun 2026)",
              "cvss": 5.0,
              "severity": "medium",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Lower-severity SSRF enabling information leakage from Exchange. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45502"
              ]
            }
          ]
        }
      },
      {
        "source": "auth_endpoint",
        "url": "https://wmail.azercell.com/Rpc/",
        "path": "/Rpc/",
        "http_status": 401,
        "auth_required": true,
        "auth_type": "Basic",
        "www_authenticate": "Basic realm=\"wmail.azercell.com\"",
        "disclosures": {
          "X-OWA-Version": "15.2.2562.17",
          "WWW-Authenticate": "Basic realm=\"wmail.azercell.com\"",
          "Set-Cookie": "TS0160ab2a=01db3e592e9ee77d132a098c89f4d0d266ad5bf411361b76bff3a7a515c460004ab2208b7eacd8c1a9ef716b6adc3f5c1149f182d1; Path=/; Domain=.wmail.azercell.com"
        },
        "severity": "high",
        "version_info": {
          "label": "Exchange SE RTM",
          "build": "15.2.2562.17",
          "release_date": "2025-07-08",
          "kb": "KB5047155",
          "is_latest": false,
          "versions_behind": 10,
          "days_old": 457,
          "cve_count": 38,
          "cves": [
            {
              "id": "CVE-2026-55008",
              "title": "Exchange Spoofing — XSS CRITICAL (Jul 2026)",
              "cvss": 9.6,
              "severity": "critical",
              "type": "Spoofing / XSS",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "XSS allowing unauthenticated spoofing with critical CVSS score of 9.6. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55008"
              ]
            },
            {
              "id": "CVE-2026-69356",
              "title": "Exchange Spoofing — Sender Impersonation (Sep 2026)",
              "cvss": 9.3,
              "severity": "critical",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Allows an attacker to impersonate a different sender in Exchange emails. CVSS 9.3. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69356"
              ]
            },
            {
              "id": "CVE-2026-69641",
              "title": "Exchange EoP — High Severity (Sep 2026)",
              "cvss": 9.1,
              "severity": "critical",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Permits attackers to obtain elevated privileges within Exchange. CVSS 9.1. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69641"
              ]
            },
            {
              "id": "CVE-2025-59249",
              "title": "Exchange EoP — Weak Authentication (Oct 2025)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Weak authentication mechanism enabling privilege escalation. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59249"
              ]
            },
            {
              "id": "CVE-2026-69355",
              "title": "Exchange RCE — Authenticated (Sep 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Authenticated attacker can execute arbitrary code on the Exchange server. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69355"
              ]
            },
            {
              "id": "CVE-2026-62913",
              "title": "Exchange RCE — Heap Buffer Overflow (Aug 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Heap buffer overflow permitting authenticated remote code execution. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62913"
              ]
            },
            {
              "id": "CVE-2026-55005",
              "title": "Exchange RCE — Heap Buffer Overflow (Jul 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Heap-based buffer overflow enabling authenticated remote code execution. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55005"
              ]
            },
            {
              "id": "CVE-2026-45504",
              "title": "Exchange EoP — SSRF (Jun 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "SSRF vulnerability enabling authenticated privilege escalation. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45504"
              ]
            },
            {
              "id": "CVE-2025-53782",
              "title": "Exchange EoP — Authentication Algorithm (Oct 2025)",
              "cvss": 8.4,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Incorrect implementation of authentication algorithm allowing an unauthorized attacker to elevate privileges locally. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53782"
              ]
            },
            {
              "id": "CVE-2026-69380",
              "title": "Exchange EoP — Missing Authorization (Sep 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Missing authorization flaw enabling low-privilege users to read and send mail as other Exchange users. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69380"
              ]
            },
            {
              "id": "CVE-2026-55007",
              "title": "Exchange RCE (Jul/Sep 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Remote code execution vulnerability. Partially addressed in July 2026 SU and fully patched in September 2026 SU. Does not affect Exchange 2016.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55007"
              ]
            },
            {
              "id": "CVE-2026-42897",
              "title": "Exchange XSS / Information Disclosure — Exploited (Jun 2026)",
              "cvss": 8.1,
              "severity": "critical",
              "type": "Information Disclosure / XSS",
              "auth_required": false,
              "exploited_in_wild": true,
              "description": "XSS flaw permitting unauthenticated remote spoofing and information disclosure. Exploited in the wild before patch release. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42897"
              ]
            },
            {
              "id": "CVE-2026-47631",
              "title": "Exchange Spoofing — Input Sanitization (Jun 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Input sanitization flaw enabling unauthenticated spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-47631"
              ]
            },
            {
              "id": "CVE-2026-45503",
              "title": "Exchange Information Disclosure — Authorization Flaw (Jun 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Authorization flaw exposing sensitive Exchange information. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45503"
              ]
            },
            {
              "id": "CVE-2026-62911",
              "title": "Exchange EoP — Replay Authentication Bypass (Aug 2026)",
              "cvss": 8.0,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Replay-based authentication bypass letting an authenticated attacker escalate privileges. Nearly 22,000 exposed servers identified as vulnerable. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62911"
              ]
            },
            {
              "id": "CVE-2026-55009",
              "title": "Exchange EoP — Unsafe Deserialization (Jul/Aug 2026)",
              "cvss": 7.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Unsafe deserialization enabling local privilege elevation. Disclosed July 2026, fully fixed in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55009"
              ]
            },
            {
              "id": "CVE-2026-55006",
              "title": "Exchange EoP — Access Controls (Jul 2026)",
              "cvss": 7.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Overly coarse access controls enabling privilege escalation. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55006"
              ]
            },
            {
              "id": "CVE-2025-33051",
              "title": "Exchange Information Disclosure (Aug 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Exposure of sensitive Exchange information to an unauthorized actor. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33051"
              ]
            },
            {
              "id": "CVE-2025-59248",
              "title": "Exchange Spoofing (Oct 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Input validation flaw permitting unauthorized spoofing. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59248"
              ]
            },
            {
              "id": "CVE-2025-64666",
              "title": "Exchange EoP — Input Validation (Dec 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Improper input validation allowing an authorized attacker to elevate privileges. Patched in December 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64666"
              ]
            },
            {
              "id": "CVE-2026-69378",
              "title": "Exchange DoS (Sep 2026)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Denial of Service",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Allows an attacker to crash the Exchange service. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69378"
              ]
            },
            {
              "id": "CVE-2026-45583",
              "title": "Exchange RCE — Code Injection (Jun 2026)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Code injection flaw permitting unauthenticated remote code execution. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45583"
              ]
            },
            {
              "id": "CVE-2026-62914",
              "title": "Exchange Spoofing — XSS (Aug 2026)",
              "cvss": 7.3,
              "severity": "high",
              "type": "Spoofing / XSS",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Cross-site scripting enabling content spoofing by authenticated users. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62914"
              ]
            },
            {
              "id": "CVE-2026-62910",
              "title": "Exchange EoP — Resource Injection CRITICAL (Aug 2026)",
              "cvss": 7.2,
              "severity": "critical",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Resource injection enabling privilege escalation. Classified critical despite CVSS 7.2 due to attack surface. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62910"
              ]
            },
            {
              "id": "CVE-2025-25005",
              "title": "Exchange Tampering (Aug 2025)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Tampering",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Input validation flaw allowing an authenticated attacker to tamper with Exchange data. Patched in August 2025 SU (first SE SU1, CU15 SU0).",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25005"
              ]
            },
            {
              "id": "CVE-2026-21527",
              "title": "Exchange Spoofing (Feb 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "UI misrepresentation enabling user spoofing by authenticated attackers. Patched in February 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-21527"
              ]
            },
            {
              "id": "CVE-2026-69361",
              "title": "Exchange Spoofing — SSRF (Sep 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Server-side request forgery issue enabling spoofing over the network. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69361"
              ]
            },
            {
              "id": "CVE-2026-69375",
              "title": "Exchange Tampering (Sep 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Tampering",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Enables unauthorized data manipulation in Exchange. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69375"
              ]
            },
            {
              "id": "CVE-2026-65813",
              "title": "Exchange EoP — SSRF (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Server-side request forgery flaw letting an authenticated attacker gain higher privileges remotely. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-65813"
              ]
            },
            {
              "id": "CVE-2026-62915",
              "title": "Exchange Security Feature Bypass (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Security Feature Bypass",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Authorization bypass allowing logged-in users to sidestep Exchange security controls. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62915"
              ]
            },
            {
              "id": "CVE-2026-62912",
              "title": "Exchange DoS — Unsafe Deserialization (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Denial of Service",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Unsafe deserialization allowing service crashes. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62912"
              ]
            },
            {
              "id": "CVE-2026-45501",
              "title": "Exchange Spoofing — SSRF (Jun 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "SSRF vulnerability allowing content spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45501"
              ]
            },
            {
              "id": "CVE-2026-45500",
              "title": "Exchange Spoofing — Output Encoding (Jun 2026)",
              "cvss": 6.1,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Output encoding flaw enabling unauthenticated spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45500"
              ]
            },
            {
              "id": "CVE-2026-69382",
              "title": "Exchange Information Disclosure (Sep 2026)",
              "cvss": 5.9,
              "severity": "medium",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Permits disclosure of restricted Exchange information. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69382"
              ]
            },
            {
              "id": "CVE-2025-25006",
              "title": "Exchange Spoofing (Aug 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Special element handling flaw enabling spoofing of Exchange content. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25006"
              ]
            },
            {
              "id": "CVE-2025-25007",
              "title": "Exchange Spoofing (Aug 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Input validation flaw permitting unauthorized spoofing of Exchange email content. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25007"
              ]
            },
            {
              "id": "CVE-2025-64667",
              "title": "Exchange Spoofing — UI Misrepresentation (Dec 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "UI misrepresentation enabling spoofing of Exchange content. Patched in December 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64667"
              ]
            },
            {
              "id": "CVE-2026-45502",
              "title": "Exchange Information Disclosure — SSRF (Jun 2026)",
              "cvss": 5.0,
              "severity": "medium",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Lower-severity SSRF enabling information leakage from Exchange. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45502"
              ]
            }
          ]
        }
      },
      {
        "source": "mapi_connect",
        "url": "https://wmail.azercell.com/mapi/emsmdb/",
        "path": "/mapi/emsmdb/",
        "http_status": 401,
        "disclosures": {
          "X-OWA-Version": "15.2.2562.17",
          "X-FEServer": "MBX19-N01",
          "WWW-Authenticate": "Negotiate",
          "Set-Cookie": "TS0160ab2a=01db3e592ec2975c8a359b72967f0c748d7659147f472d96a3af576cf8c18c64f6c51c750496e22d4db6188c1e87b84d6cff4f75d7; Path=/; Domain=.wmail.azercell.com"
        },
        "severity": "high"
      },
      {
        "source": "autodiscover_xml",
        "url": "https://wmail.azercell.com/autodiscover/autodiscover.xml",
        "path": "/autodiscover/autodiscover.xml",
        "http_status": 404,
        "disclosures": {
          "Set-Cookie": "TS0160ab2a=01db3e592e9ddfad432e0c90892ca053f248443073aa71f1b82a75c5ff39f8ca090fc779d9d312ca7b0171e78ac026445ed7db6ad5; Path=/; Domain=.wmail.azercell.com"
        },
        "severity": "low"
      },
      {
        "source": "ews_soap",
        "url": "https://wmail.azercell.com/EWS/Exchange.asmx",
        "path": "/EWS/Exchange.asmx",
        "http_status": 401,
        "disclosures": {
          "X-OWA-Version": "15.2.2562.17",
          "X-FEServer": "MBX19-N01",
          "WWW-Authenticate": "Basic realm=\"wmail.azercell.com\"",
          "Set-Cookie": "TS0160ab2a=01db3e592e7edfa44836cf0195c7fe92c492ed717277f989f29c8bc25584f2a23409c29ea5895d7654847696750ee709db0de443c4; Path=/; Domain=.wmail.azercell.com"
        },
        "severity": "high"
      },
      {
        "source": "owa_fingerprint",
        "url": "https://wmail.azercell.com/_api/web",
        "path": "/_api/web",
        "http_status": 404,
        "disclosures": {
          "Set-Cookie": "TS0160ab2a=01db3e592ed959162eb52b267b26441a44d2c795337b945d3f18d3e45795e33dcb70baf66032823b21e8c5d5ebacf4e33c456c14c7; Path=/; Domain=.wmail.azercell.com"
        },
        "severity": "low",
        "version_info": {}
      },
      {
        "source": "auth_endpoint",
        "url": "https://wmail.azercell.com/EWS/Exchange.asmx",
        "path": "/EWS/Exchange.asmx",
        "http_status": 401,
        "auth_required": true,
        "auth_type": "Basic",
        "www_authenticate": "Basic realm=\"wmail.azercell.com\"",
        "disclosures": {
          "X-OWA-Version": "15.2.2562.17",
          "X-FEServer": "MBX19-N01",
          "X-WSSecurity-For": "None",
          "WWW-Authenticate": "Basic realm=\"wmail.azercell.com\"",
          "Set-Cookie": "TS0160ab2a=01db3e592e197063ef8619aff0579842f1d4c3dee017d0340cd94f21b83de4c3195558f2896cb2d7460ef2de9fb505c7e9f89c7db7; Path=/; Domain=.wmail.azercell.com"
        },
        "severity": "high",
        "version_info": {
          "label": "Exchange SE RTM",
          "build": "15.2.2562.17",
          "release_date": "2025-07-08",
          "kb": "KB5047155",
          "is_latest": false,
          "versions_behind": 10,
          "days_old": 457,
          "cve_count": 38,
          "cves": [
            {
              "id": "CVE-2026-55008",
              "title": "Exchange Spoofing — XSS CRITICAL (Jul 2026)",
              "cvss": 9.6,
              "severity": "critical",
              "type": "Spoofing / XSS",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "XSS allowing unauthenticated spoofing with critical CVSS score of 9.6. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55008"
              ]
            },
            {
              "id": "CVE-2026-69356",
              "title": "Exchange Spoofing — Sender Impersonation (Sep 2026)",
              "cvss": 9.3,
              "severity": "critical",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Allows an attacker to impersonate a different sender in Exchange emails. CVSS 9.3. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69356"
              ]
            },
            {
              "id": "CVE-2026-69641",
              "title": "Exchange EoP — High Severity (Sep 2026)",
              "cvss": 9.1,
              "severity": "critical",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Permits attackers to obtain elevated privileges within Exchange. CVSS 9.1. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69641"
              ]
            },
            {
              "id": "CVE-2025-59249",
              "title": "Exchange EoP — Weak Authentication (Oct 2025)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Weak authentication mechanism enabling privilege escalation. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59249"
              ]
            },
            {
              "id": "CVE-2026-69355",
              "title": "Exchange RCE — Authenticated (Sep 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Authenticated attacker can execute arbitrary code on the Exchange server. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69355"
              ]
            },
            {
              "id": "CVE-2026-62913",
              "title": "Exchange RCE — Heap Buffer Overflow (Aug 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Heap buffer overflow permitting authenticated remote code execution. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62913"
              ]
            },
            {
              "id": "CVE-2026-55005",
              "title": "Exchange RCE — Heap Buffer Overflow (Jul 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Heap-based buffer overflow enabling authenticated remote code execution. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55005"
              ]
            },
            {
              "id": "CVE-2026-45504",
              "title": "Exchange EoP — SSRF (Jun 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "SSRF vulnerability enabling authenticated privilege escalation. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45504"
              ]
            },
            {
              "id": "CVE-2025-53782",
              "title": "Exchange EoP — Authentication Algorithm (Oct 2025)",
              "cvss": 8.4,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Incorrect implementation of authentication algorithm allowing an unauthorized attacker to elevate privileges locally. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53782"
              ]
            },
            {
              "id": "CVE-2026-69380",
              "title": "Exchange EoP — Missing Authorization (Sep 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Missing authorization flaw enabling low-privilege users to read and send mail as other Exchange users. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69380"
              ]
            },
            {
              "id": "CVE-2026-55007",
              "title": "Exchange RCE (Jul/Sep 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Remote code execution vulnerability. Partially addressed in July 2026 SU and fully patched in September 2026 SU. Does not affect Exchange 2016.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55007"
              ]
            },
            {
              "id": "CVE-2026-42897",
              "title": "Exchange XSS / Information Disclosure — Exploited (Jun 2026)",
              "cvss": 8.1,
              "severity": "critical",
              "type": "Information Disclosure / XSS",
              "auth_required": false,
              "exploited_in_wild": true,
              "description": "XSS flaw permitting unauthenticated remote spoofing and information disclosure. Exploited in the wild before patch release. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42897"
              ]
            },
            {
              "id": "CVE-2026-47631",
              "title": "Exchange Spoofing — Input Sanitization (Jun 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Input sanitization flaw enabling unauthenticated spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-47631"
              ]
            },
            {
              "id": "CVE-2026-45503",
              "title": "Exchange Information Disclosure — Authorization Flaw (Jun 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Authorization flaw exposing sensitive Exchange information. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45503"
              ]
            },
            {
              "id": "CVE-2026-62911",
              "title": "Exchange EoP — Replay Authentication Bypass (Aug 2026)",
              "cvss": 8.0,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Replay-based authentication bypass letting an authenticated attacker escalate privileges. Nearly 22,000 exposed servers identified as vulnerable. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62911"
              ]
            },
            {
              "id": "CVE-2026-55009",
              "title": "Exchange EoP — Unsafe Deserialization (Jul/Aug 2026)",
              "cvss": 7.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Unsafe deserialization enabling local privilege elevation. Disclosed July 2026, fully fixed in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55009"
              ]
            },
            {
              "id": "CVE-2026-55006",
              "title": "Exchange EoP — Access Controls (Jul 2026)",
              "cvss": 7.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Overly coarse access controls enabling privilege escalation. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55006"
              ]
            },
            {
              "id": "CVE-2025-33051",
              "title": "Exchange Information Disclosure (Aug 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Exposure of sensitive Exchange information to an unauthorized actor. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33051"
              ]
            },
            {
              "id": "CVE-2025-59248",
              "title": "Exchange Spoofing (Oct 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Input validation flaw permitting unauthorized spoofing. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59248"
              ]
            },
            {
              "id": "CVE-2025-64666",
              "title": "Exchange EoP — Input Validation (Dec 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Improper input validation allowing an authorized attacker to elevate privileges. Patched in December 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64666"
              ]
            },
            {
              "id": "CVE-2026-69378",
              "title": "Exchange DoS (Sep 2026)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Denial of Service",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Allows an attacker to crash the Exchange service. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69378"
              ]
            },
            {
              "id": "CVE-2026-45583",
              "title": "Exchange RCE — Code Injection (Jun 2026)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Code injection flaw permitting unauthenticated remote code execution. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45583"
              ]
            },
            {
              "id": "CVE-2026-62914",
              "title": "Exchange Spoofing — XSS (Aug 2026)",
              "cvss": 7.3,
              "severity": "high",
              "type": "Spoofing / XSS",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Cross-site scripting enabling content spoofing by authenticated users. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62914"
              ]
            },
            {
              "id": "CVE-2026-62910",
              "title": "Exchange EoP — Resource Injection CRITICAL (Aug 2026)",
              "cvss": 7.2,
              "severity": "critical",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Resource injection enabling privilege escalation. Classified critical despite CVSS 7.2 due to attack surface. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62910"
              ]
            },
            {
              "id": "CVE-2025-25005",
              "title": "Exchange Tampering (Aug 2025)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Tampering",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Input validation flaw allowing an authenticated attacker to tamper with Exchange data. Patched in August 2025 SU (first SE SU1, CU15 SU0).",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25005"
              ]
            },
            {
              "id": "CVE-2026-21527",
              "title": "Exchange Spoofing (Feb 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "UI misrepresentation enabling user spoofing by authenticated attackers. Patched in February 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-21527"
              ]
            },
            {
              "id": "CVE-2026-69361",
              "title": "Exchange Spoofing — SSRF (Sep 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Server-side request forgery issue enabling spoofing over the network. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69361"
              ]
            },
            {
              "id": "CVE-2026-69375",
              "title": "Exchange Tampering (Sep 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Tampering",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Enables unauthorized data manipulation in Exchange. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69375"
              ]
            },
            {
              "id": "CVE-2026-65813",
              "title": "Exchange EoP — SSRF (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Server-side request forgery flaw letting an authenticated attacker gain higher privileges remotely. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-65813"
              ]
            },
            {
              "id": "CVE-2026-62915",
              "title": "Exchange Security Feature Bypass (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Security Feature Bypass",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Authorization bypass allowing logged-in users to sidestep Exchange security controls. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62915"
              ]
            },
            {
              "id": "CVE-2026-62912",
              "title": "Exchange DoS — Unsafe Deserialization (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Denial of Service",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Unsafe deserialization allowing service crashes. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62912"
              ]
            },
            {
              "id": "CVE-2026-45501",
              "title": "Exchange Spoofing — SSRF (Jun 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "SSRF vulnerability allowing content spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45501"
              ]
            },
            {
              "id": "CVE-2026-45500",
              "title": "Exchange Spoofing — Output Encoding (Jun 2026)",
              "cvss": 6.1,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Output encoding flaw enabling unauthenticated spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45500"
              ]
            },
            {
              "id": "CVE-2026-69382",
              "title": "Exchange Information Disclosure (Sep 2026)",
              "cvss": 5.9,
              "severity": "medium",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Permits disclosure of restricted Exchange information. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69382"
              ]
            },
            {
              "id": "CVE-2025-25006",
              "title": "Exchange Spoofing (Aug 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Special element handling flaw enabling spoofing of Exchange content. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25006"
              ]
            },
            {
              "id": "CVE-2025-25007",
              "title": "Exchange Spoofing (Aug 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Input validation flaw permitting unauthorized spoofing of Exchange email content. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25007"
              ]
            },
            {
              "id": "CVE-2025-64667",
              "title": "Exchange Spoofing — UI Misrepresentation (Dec 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "UI misrepresentation enabling spoofing of Exchange content. Patched in December 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64667"
              ]
            },
            {
              "id": "CVE-2026-45502",
              "title": "Exchange Information Disclosure — SSRF (Jun 2026)",
              "cvss": 5.0,
              "severity": "medium",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Lower-severity SSRF enabling information leakage from Exchange. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45502"
              ]
            }
          ]
        }
      },
      {
        "source": "mapi_connect",
        "url": "https://wmail.azercell.com/mapi/",
        "path": "/mapi/",
        "http_status": 401,
        "disclosures": {
          "X-OWA-Version": "15.2.2562.17",
          "X-FEServer": "MBX19-N01",
          "WWW-Authenticate": "Negotiate",
          "Set-Cookie": "TS0160ab2a=01db3e592eb03e16b43f4c8a638e83b47a98a5fe54335d16925ea75b2ee1a910404b53056286ed7a2392acac59af2dbf5ee7ba1787; Path=/; Domain=.wmail.azercell.com"
        },
        "severity": "high"
      },
      {
        "source": "autodiscover_v2",
        "url": "https://wmail.azercell.com/.well-known/autodiscover.json?Email=autodiscover@azercell.com&Protocol=Ews",
        "path": "/.well-known/autodiscover.json",
        "http_status": 404,
        "email": "autodiscover@azercell.com",
        "email_exists": false,
        "protocol": "Ews",
        "disclosures": {
          "Set-Cookie": "TS0160ab2a=01db3e592e728f9cb057bc71bf9736d69d2d65d3660ded71bb888b27495f99ac7310ed0cd0d596d77418f054545a85a816fec2d6eb; Path=/; Domain=.wmail.azercell.com"
        },
        "severity": "info"
      },
      {
        "source": "owa_fingerprint",
        "url": "https://wmail.azercell.com/owa/auth/errorFE.aspx",
        "path": "/owa/auth/errorFE.aspx",
        "http_status": 500,
        "disclosures": {
          "X-OWA-Version": "15.2.2562.17",
          "X-FEServer": "MBX19-N01",
          "Set-Cookie": "TS0160ab2a=01db3e592e3ad992ea64d0595dcc3bb5ff9fb5e67448a0e1d60306272a02e1efb2bb47eb312515dd5502f70b9725db27f3f49f21c4; Path=/; Domain=.wmail.azercell.com",
          "body:error_server": "MBX19-N01",
          "body:internal_hostname": "MBX19-N01",
          "body:owa_build_label": "15.2.2562"
        },
        "severity": "high",
        "version_info": {
          "label": "Exchange SE RTM",
          "build": "15.2.2562.17",
          "release_date": "2025-07-08",
          "kb": "KB5047155",
          "is_latest": false,
          "versions_behind": 10,
          "days_old": 457,
          "cve_count": 38,
          "cves": [
            {
              "id": "CVE-2026-55008",
              "title": "Exchange Spoofing — XSS CRITICAL (Jul 2026)",
              "cvss": 9.6,
              "severity": "critical",
              "type": "Spoofing / XSS",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "XSS allowing unauthenticated spoofing with critical CVSS score of 9.6. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55008"
              ]
            },
            {
              "id": "CVE-2026-69356",
              "title": "Exchange Spoofing — Sender Impersonation (Sep 2026)",
              "cvss": 9.3,
              "severity": "critical",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Allows an attacker to impersonate a different sender in Exchange emails. CVSS 9.3. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69356"
              ]
            },
            {
              "id": "CVE-2026-69641",
              "title": "Exchange EoP — High Severity (Sep 2026)",
              "cvss": 9.1,
              "severity": "critical",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Permits attackers to obtain elevated privileges within Exchange. CVSS 9.1. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69641"
              ]
            },
            {
              "id": "CVE-2025-59249",
              "title": "Exchange EoP — Weak Authentication (Oct 2025)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Weak authentication mechanism enabling privilege escalation. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59249"
              ]
            },
            {
              "id": "CVE-2026-69355",
              "title": "Exchange RCE — Authenticated (Sep 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Authenticated attacker can execute arbitrary code on the Exchange server. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69355"
              ]
            },
            {
              "id": "CVE-2026-62913",
              "title": "Exchange RCE — Heap Buffer Overflow (Aug 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Heap buffer overflow permitting authenticated remote code execution. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62913"
              ]
            },
            {
              "id": "CVE-2026-55005",
              "title": "Exchange RCE — Heap Buffer Overflow (Jul 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Heap-based buffer overflow enabling authenticated remote code execution. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55005"
              ]
            },
            {
              "id": "CVE-2026-45504",
              "title": "Exchange EoP — SSRF (Jun 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "SSRF vulnerability enabling authenticated privilege escalation. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45504"
              ]
            },
            {
              "id": "CVE-2025-53782",
              "title": "Exchange EoP — Authentication Algorithm (Oct 2025)",
              "cvss": 8.4,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Incorrect implementation of authentication algorithm allowing an unauthorized attacker to elevate privileges locally. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53782"
              ]
            },
            {
              "id": "CVE-2026-69380",
              "title": "Exchange EoP — Missing Authorization (Sep 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Missing authorization flaw enabling low-privilege users to read and send mail as other Exchange users. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69380"
              ]
            },
            {
              "id": "CVE-2026-55007",
              "title": "Exchange RCE (Jul/Sep 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Remote code execution vulnerability. Partially addressed in July 2026 SU and fully patched in September 2026 SU. Does not affect Exchange 2016.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55007"
              ]
            },
            {
              "id": "CVE-2026-42897",
              "title": "Exchange XSS / Information Disclosure — Exploited (Jun 2026)",
              "cvss": 8.1,
              "severity": "critical",
              "type": "Information Disclosure / XSS",
              "auth_required": false,
              "exploited_in_wild": true,
              "description": "XSS flaw permitting unauthenticated remote spoofing and information disclosure. Exploited in the wild before patch release. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42897"
              ]
            },
            {
              "id": "CVE-2026-47631",
              "title": "Exchange Spoofing — Input Sanitization (Jun 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Input sanitization flaw enabling unauthenticated spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-47631"
              ]
            },
            {
              "id": "CVE-2026-45503",
              "title": "Exchange Information Disclosure — Authorization Flaw (Jun 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Authorization flaw exposing sensitive Exchange information. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45503"
              ]
            },
            {
              "id": "CVE-2026-62911",
              "title": "Exchange EoP — Replay Authentication Bypass (Aug 2026)",
              "cvss": 8.0,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Replay-based authentication bypass letting an authenticated attacker escalate privileges. Nearly 22,000 exposed servers identified as vulnerable. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62911"
              ]
            },
            {
              "id": "CVE-2026-55009",
              "title": "Exchange EoP — Unsafe Deserialization (Jul/Aug 2026)",
              "cvss": 7.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Unsafe deserialization enabling local privilege elevation. Disclosed July 2026, fully fixed in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55009"
              ]
            },
            {
              "id": "CVE-2026-55006",
              "title": "Exchange EoP — Access Controls (Jul 2026)",
              "cvss": 7.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Overly coarse access controls enabling privilege escalation. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55006"
              ]
            },
            {
              "id": "CVE-2025-33051",
              "title": "Exchange Information Disclosure (Aug 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Exposure of sensitive Exchange information to an unauthorized actor. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33051"
              ]
            },
            {
              "id": "CVE-2025-59248",
              "title": "Exchange Spoofing (Oct 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Input validation flaw permitting unauthorized spoofing. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59248"
              ]
            },
            {
              "id": "CVE-2025-64666",
              "title": "Exchange EoP — Input Validation (Dec 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Improper input validation allowing an authorized attacker to elevate privileges. Patched in December 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64666"
              ]
            },
            {
              "id": "CVE-2026-69378",
              "title": "Exchange DoS (Sep 2026)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Denial of Service",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Allows an attacker to crash the Exchange service. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69378"
              ]
            },
            {
              "id": "CVE-2026-45583",
              "title": "Exchange RCE — Code Injection (Jun 2026)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Code injection flaw permitting unauthenticated remote code execution. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45583"
              ]
            },
            {
              "id": "CVE-2026-62914",
              "title": "Exchange Spoofing — XSS (Aug 2026)",
              "cvss": 7.3,
              "severity": "high",
              "type": "Spoofing / XSS",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Cross-site scripting enabling content spoofing by authenticated users. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62914"
              ]
            },
            {
              "id": "CVE-2026-62910",
              "title": "Exchange EoP — Resource Injection CRITICAL (Aug 2026)",
              "cvss": 7.2,
              "severity": "critical",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Resource injection enabling privilege escalation. Classified critical despite CVSS 7.2 due to attack surface. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62910"
              ]
            },
            {
              "id": "CVE-2025-25005",
              "title": "Exchange Tampering (Aug 2025)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Tampering",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Input validation flaw allowing an authenticated attacker to tamper with Exchange data. Patched in August 2025 SU (first SE SU1, CU15 SU0).",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25005"
              ]
            },
            {
              "id": "CVE-2026-21527",
              "title": "Exchange Spoofing (Feb 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "UI misrepresentation enabling user spoofing by authenticated attackers. Patched in February 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-21527"
              ]
            },
            {
              "id": "CVE-2026-69361",
              "title": "Exchange Spoofing — SSRF (Sep 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Server-side request forgery issue enabling spoofing over the network. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69361"
              ]
            },
            {
              "id": "CVE-2026-69375",
              "title": "Exchange Tampering (Sep 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Tampering",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Enables unauthorized data manipulation in Exchange. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69375"
              ]
            },
            {
              "id": "CVE-2026-65813",
              "title": "Exchange EoP — SSRF (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Server-side request forgery flaw letting an authenticated attacker gain higher privileges remotely. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-65813"
              ]
            },
            {
              "id": "CVE-2026-62915",
              "title": "Exchange Security Feature Bypass (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Security Feature Bypass",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Authorization bypass allowing logged-in users to sidestep Exchange security controls. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62915"
              ]
            },
            {
              "id": "CVE-2026-62912",
              "title": "Exchange DoS — Unsafe Deserialization (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Denial of Service",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Unsafe deserialization allowing service crashes. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62912"
              ]
            },
            {
              "id": "CVE-2026-45501",
              "title": "Exchange Spoofing — SSRF (Jun 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "SSRF vulnerability allowing content spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45501"
              ]
            },
            {
              "id": "CVE-2026-45500",
              "title": "Exchange Spoofing — Output Encoding (Jun 2026)",
              "cvss": 6.1,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Output encoding flaw enabling unauthenticated spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45500"
              ]
            },
            {
              "id": "CVE-2026-69382",
              "title": "Exchange Information Disclosure (Sep 2026)",
              "cvss": 5.9,
              "severity": "medium",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Permits disclosure of restricted Exchange information. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69382"
              ]
            },
            {
              "id": "CVE-2025-25006",
              "title": "Exchange Spoofing (Aug 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Special element handling flaw enabling spoofing of Exchange content. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25006"
              ]
            },
            {
              "id": "CVE-2025-25007",
              "title": "Exchange Spoofing (Aug 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Input validation flaw permitting unauthorized spoofing of Exchange email content. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25007"
              ]
            },
            {
              "id": "CVE-2025-64667",
              "title": "Exchange Spoofing — UI Misrepresentation (Dec 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "UI misrepresentation enabling spoofing of Exchange content. Patched in December 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64667"
              ]
            },
            {
              "id": "CVE-2026-45502",
              "title": "Exchange Information Disclosure — SSRF (Jun 2026)",
              "cvss": 5.0,
              "severity": "medium",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Lower-severity SSRF enabling information leakage from Exchange. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45502"
              ]
            }
          ]
        }
      },
      {
        "source": "owa_fingerprint",
        "url": "https://wmail.azercell.com/aspnet_client/",
        "path": "/aspnet_client/",
        "http_status": 500,
        "disclosures": {
          "Set-Cookie": "TS0160ab2a=01db3e592e74ba3e395eed4bce0492c13b177acb15b2b125e7f53f04fd3c497217d39f7157f8138e19b29be6c651ddee0e0a71f188; Path=/; Domain=.wmail.azercell.com"
        },
        "severity": "low",
        "version_info": {}
      },
      {
        "source": "owa_fingerprint",
        "url": "https://wmail.azercell.com/owa/auth/expiredpassword.aspx",
        "path": "/owa/auth/expiredpassword.aspx",
        "http_status": 200,
        "disclosures": {
          "Set-Cookie": "TS0160ab2a=01db3e592eb8607850963e2e93faacc31f161aea6fa48146ecbce2291cd9fb1f86f382807c2572b6123c0eb374519559b175ef0364; Path=/; Domain=.wmail.azercell.com"
        },
        "severity": "low",
        "version_info": {}
      },
      {
        "source": "owa_fingerprint",
        "url": "https://wmail.azercell.com/cscp/",
        "path": "/cscp/",
        "http_status": 404,
        "disclosures": {
          "Set-Cookie": "TS0160ab2a=01db3e592e0272753b4e97f2253ddb38034e8800d26eb40733b23947e21b0731990af3a539b8358b9acdfc8ebfca57b08de15310c8; Path=/; Domain=.wmail.azercell.com"
        },
        "severity": "low",
        "version_info": {}
      },
      {
        "source": "autodiscover_v2",
        "url": "https://wmail.azercell.com/autodiscover/autodiscover.json?Email=autodiscover@azercell.com&Protocol=Ews",
        "path": "/autodiscover/autodiscover.json",
        "http_status": 404,
        "email": "autodiscover@azercell.com",
        "email_exists": false,
        "protocol": "Ews",
        "disclosures": {
          "Set-Cookie": "TS0160ab2a=01db3e592e5eaabf6882342741db9067e2353db35db0b54b7458292703fdfcdc3f94e37e039daa6852e8139605eaabed00db42af88; Path=/; Domain=.wmail.azercell.com"
        },
        "severity": "info"
      },
      {
        "source": "auth_endpoint",
        "url": "https://wmail.azercell.com/EWS/Services.wsdl",
        "path": "/EWS/Services.wsdl",
        "http_status": 401,
        "auth_required": true,
        "auth_type": "Basic",
        "www_authenticate": "Basic realm=\"wmail.azercell.com\"",
        "disclosures": {
          "X-OWA-Version": "15.2.2562.17",
          "X-FEServer": "MBX19-N01",
          "X-WSSecurity-For": "None",
          "WWW-Authenticate": "Basic realm=\"wmail.azercell.com\"",
          "Set-Cookie": "TS0160ab2a=01db3e592e2731acf8e2eaa95da023f05c18c7fe678761388b403b2cb5fce552f2e3d72638cc0b07c5a305159f27a48c13130f9e0f; Path=/; Domain=.wmail.azercell.com"
        },
        "severity": "high",
        "version_info": {
          "label": "Exchange SE RTM",
          "build": "15.2.2562.17",
          "release_date": "2025-07-08",
          "kb": "KB5047155",
          "is_latest": false,
          "versions_behind": 10,
          "days_old": 457,
          "cve_count": 38,
          "cves": [
            {
              "id": "CVE-2026-55008",
              "title": "Exchange Spoofing — XSS CRITICAL (Jul 2026)",
              "cvss": 9.6,
              "severity": "critical",
              "type": "Spoofing / XSS",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "XSS allowing unauthenticated spoofing with critical CVSS score of 9.6. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55008"
              ]
            },
            {
              "id": "CVE-2026-69356",
              "title": "Exchange Spoofing — Sender Impersonation (Sep 2026)",
              "cvss": 9.3,
              "severity": "critical",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Allows an attacker to impersonate a different sender in Exchange emails. CVSS 9.3. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69356"
              ]
            },
            {
              "id": "CVE-2026-69641",
              "title": "Exchange EoP — High Severity (Sep 2026)",
              "cvss": 9.1,
              "severity": "critical",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Permits attackers to obtain elevated privileges within Exchange. CVSS 9.1. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69641"
              ]
            },
            {
              "id": "CVE-2025-59249",
              "title": "Exchange EoP — Weak Authentication (Oct 2025)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Weak authentication mechanism enabling privilege escalation. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59249"
              ]
            },
            {
              "id": "CVE-2026-69355",
              "title": "Exchange RCE — Authenticated (Sep 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Authenticated attacker can execute arbitrary code on the Exchange server. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69355"
              ]
            },
            {
              "id": "CVE-2026-62913",
              "title": "Exchange RCE — Heap Buffer Overflow (Aug 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Heap buffer overflow permitting authenticated remote code execution. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62913"
              ]
            },
            {
              "id": "CVE-2026-55005",
              "title": "Exchange RCE — Heap Buffer Overflow (Jul 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Heap-based buffer overflow enabling authenticated remote code execution. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55005"
              ]
            },
            {
              "id": "CVE-2026-45504",
              "title": "Exchange EoP — SSRF (Jun 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "SSRF vulnerability enabling authenticated privilege escalation. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45504"
              ]
            },
            {
              "id": "CVE-2025-53782",
              "title": "Exchange EoP — Authentication Algorithm (Oct 2025)",
              "cvss": 8.4,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Incorrect implementation of authentication algorithm allowing an unauthorized attacker to elevate privileges locally. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53782"
              ]
            },
            {
              "id": "CVE-2026-69380",
              "title": "Exchange EoP — Missing Authorization (Sep 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Missing authorization flaw enabling low-privilege users to read and send mail as other Exchange users. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69380"
              ]
            },
            {
              "id": "CVE-2026-55007",
              "title": "Exchange RCE (Jul/Sep 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Remote code execution vulnerability. Partially addressed in July 2026 SU and fully patched in September 2026 SU. Does not affect Exchange 2016.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55007"
              ]
            },
            {
              "id": "CVE-2026-42897",
              "title": "Exchange XSS / Information Disclosure — Exploited (Jun 2026)",
              "cvss": 8.1,
              "severity": "critical",
              "type": "Information Disclosure / XSS",
              "auth_required": false,
              "exploited_in_wild": true,
              "description": "XSS flaw permitting unauthenticated remote spoofing and information disclosure. Exploited in the wild before patch release. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42897"
              ]
            },
            {
              "id": "CVE-2026-47631",
              "title": "Exchange Spoofing — Input Sanitization (Jun 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Input sanitization flaw enabling unauthenticated spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-47631"
              ]
            },
            {
              "id": "CVE-2026-45503",
              "title": "Exchange Information Disclosure — Authorization Flaw (Jun 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Authorization flaw exposing sensitive Exchange information. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45503"
              ]
            },
            {
              "id": "CVE-2026-62911",
              "title": "Exchange EoP — Replay Authentication Bypass (Aug 2026)",
              "cvss": 8.0,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Replay-based authentication bypass letting an authenticated attacker escalate privileges. Nearly 22,000 exposed servers identified as vulnerable. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62911"
              ]
            },
            {
              "id": "CVE-2026-55009",
              "title": "Exchange EoP — Unsafe Deserialization (Jul/Aug 2026)",
              "cvss": 7.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Unsafe deserialization enabling local privilege elevation. Disclosed July 2026, fully fixed in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55009"
              ]
            },
            {
              "id": "CVE-2026-55006",
              "title": "Exchange EoP — Access Controls (Jul 2026)",
              "cvss": 7.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Overly coarse access controls enabling privilege escalation. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55006"
              ]
            },
            {
              "id": "CVE-2025-33051",
              "title": "Exchange Information Disclosure (Aug 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Exposure of sensitive Exchange information to an unauthorized actor. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33051"
              ]
            },
            {
              "id": "CVE-2025-59248",
              "title": "Exchange Spoofing (Oct 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Input validation flaw permitting unauthorized spoofing. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59248"
              ]
            },
            {
              "id": "CVE-2025-64666",
              "title": "Exchange EoP — Input Validation (Dec 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Improper input validation allowing an authorized attacker to elevate privileges. Patched in December 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64666"
              ]
            },
            {
              "id": "CVE-2026-69378",
              "title": "Exchange DoS (Sep 2026)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Denial of Service",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Allows an attacker to crash the Exchange service. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69378"
              ]
            },
            {
              "id": "CVE-2026-45583",
              "title": "Exchange RCE — Code Injection (Jun 2026)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Code injection flaw permitting unauthenticated remote code execution. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45583"
              ]
            },
            {
              "id": "CVE-2026-62914",
              "title": "Exchange Spoofing — XSS (Aug 2026)",
              "cvss": 7.3,
              "severity": "high",
              "type": "Spoofing / XSS",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Cross-site scripting enabling content spoofing by authenticated users. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62914"
              ]
            },
            {
              "id": "CVE-2026-62910",
              "title": "Exchange EoP — Resource Injection CRITICAL (Aug 2026)",
              "cvss": 7.2,
              "severity": "critical",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Resource injection enabling privilege escalation. Classified critical despite CVSS 7.2 due to attack surface. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62910"
              ]
            },
            {
              "id": "CVE-2025-25005",
              "title": "Exchange Tampering (Aug 2025)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Tampering",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Input validation flaw allowing an authenticated attacker to tamper with Exchange data. Patched in August 2025 SU (first SE SU1, CU15 SU0).",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25005"
              ]
            },
            {
              "id": "CVE-2026-21527",
              "title": "Exchange Spoofing (Feb 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "UI misrepresentation enabling user spoofing by authenticated attackers. Patched in February 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-21527"
              ]
            },
            {
              "id": "CVE-2026-69361",
              "title": "Exchange Spoofing — SSRF (Sep 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Server-side request forgery issue enabling spoofing over the network. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69361"
              ]
            },
            {
              "id": "CVE-2026-69375",
              "title": "Exchange Tampering (Sep 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Tampering",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Enables unauthorized data manipulation in Exchange. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69375"
              ]
            },
            {
              "id": "CVE-2026-65813",
              "title": "Exchange EoP — SSRF (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Server-side request forgery flaw letting an authenticated attacker gain higher privileges remotely. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-65813"
              ]
            },
            {
              "id": "CVE-2026-62915",
              "title": "Exchange Security Feature Bypass (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Security Feature Bypass",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Authorization bypass allowing logged-in users to sidestep Exchange security controls. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62915"
              ]
            },
            {
              "id": "CVE-2026-62912",
              "title": "Exchange DoS — Unsafe Deserialization (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Denial of Service",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Unsafe deserialization allowing service crashes. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62912"
              ]
            },
            {
              "id": "CVE-2026-45501",
              "title": "Exchange Spoofing — SSRF (Jun 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "SSRF vulnerability allowing content spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45501"
              ]
            },
            {
              "id": "CVE-2026-45500",
              "title": "Exchange Spoofing — Output Encoding (Jun 2026)",
              "cvss": 6.1,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Output encoding flaw enabling unauthenticated spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45500"
              ]
            },
            {
              "id": "CVE-2026-69382",
              "title": "Exchange Information Disclosure (Sep 2026)",
              "cvss": 5.9,
              "severity": "medium",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Permits disclosure of restricted Exchange information. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69382"
              ]
            },
            {
              "id": "CVE-2025-25006",
              "title": "Exchange Spoofing (Aug 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Special element handling flaw enabling spoofing of Exchange content. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25006"
              ]
            },
            {
              "id": "CVE-2025-25007",
              "title": "Exchange Spoofing (Aug 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Input validation flaw permitting unauthorized spoofing of Exchange email content. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25007"
              ]
            },
            {
              "id": "CVE-2025-64667",
              "title": "Exchange Spoofing — UI Misrepresentation (Dec 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "UI misrepresentation enabling spoofing of Exchange content. Patched in December 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64667"
              ]
            },
            {
              "id": "CVE-2026-45502",
              "title": "Exchange Information Disclosure — SSRF (Jun 2026)",
              "cvss": 5.0,
              "severity": "medium",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Lower-severity SSRF enabling information leakage from Exchange. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45502"
              ]
            }
          ]
        }
      },
      {
        "source": "owa_fingerprint",
        "url": "https://wmail.azercell.com/owa/auth/logon.aspx",
        "path": "/owa/auth/logon.aspx",
        "http_status": 200,
        "disclosures": {
          "Set-Cookie": "TS0160ab2a=01db3e592e51fb8f321a547f997aa5ed24a2f0433c276275346cfb610d1e44e704d161adb31a640205d40b403b792e5175b9390d4c; Path=/; Domain=.wmail.azercell.com",
          "body:owa_build_label": "15.2.2562"
        },
        "severity": "low",
        "version_info": {}
      },
      {
        "source": "mapi_connect",
        "url": "https://wmail.azercell.com/mapi/nspi/",
        "path": "/mapi/nspi/",
        "http_status": 401,
        "disclosures": {
          "X-OWA-Version": "15.2.2562.17",
          "X-FEServer": "MBX19-N01",
          "WWW-Authenticate": "Negotiate",
          "Set-Cookie": "TS0160ab2a=01db3e592eb7102dec7b28aaa22ff508c0de00ef5ae36dc833c920d801633f9c4144abf7d03226aceaa7a535302ae5e5696346d6de; Path=/; Domain=.wmail.azercell.com"
        },
        "severity": "high"
      },
      {
        "source": "auth_endpoint",
        "url": "https://wmail.azercell.com/mapi/emsmdb/",
        "path": "/mapi/emsmdb/",
        "http_status": 401,
        "auth_required": true,
        "auth_type": "Negotiate",
        "www_authenticate": "Negotiate",
        "disclosures": {
          "X-OWA-Version": "15.2.2562.17",
          "X-FEServer": "MBX19-N01",
          "WWW-Authenticate": "Negotiate",
          "Set-Cookie": "TS0160ab2a=01db3e592e624f3e263c61af01a38ccac488830dd11889f9935d17d785407ec7e506e9fbbb92e3aefec1bf2a013e276db7541ab401; Path=/; Domain=.wmail.azercell.com",
          "ntlm:target_name": "AZERCELL",
          "ntlm:nb_domain_name": "AZERCELL",
          "ntlm:nb_computer_name": "MBX19-N01",
          "ntlm:dns_domain_name": "azercell.com",
          "ntlm:dns_computer_name": "MBX19-N01.azercell.com",
          "ntlm:dns_tree_name": "azercell.com"
        },
        "severity": "high",
        "version_info": {
          "label": "Exchange SE RTM",
          "build": "15.2.2562.17",
          "release_date": "2025-07-08",
          "kb": "KB5047155",
          "is_latest": false,
          "versions_behind": 10,
          "days_old": 457,
          "cve_count": 38,
          "cves": [
            {
              "id": "CVE-2026-55008",
              "title": "Exchange Spoofing — XSS CRITICAL (Jul 2026)",
              "cvss": 9.6,
              "severity": "critical",
              "type": "Spoofing / XSS",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "XSS allowing unauthenticated spoofing with critical CVSS score of 9.6. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55008"
              ]
            },
            {
              "id": "CVE-2026-69356",
              "title": "Exchange Spoofing — Sender Impersonation (Sep 2026)",
              "cvss": 9.3,
              "severity": "critical",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Allows an attacker to impersonate a different sender in Exchange emails. CVSS 9.3. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69356"
              ]
            },
            {
              "id": "CVE-2026-69641",
              "title": "Exchange EoP — High Severity (Sep 2026)",
              "cvss": 9.1,
              "severity": "critical",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Permits attackers to obtain elevated privileges within Exchange. CVSS 9.1. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69641"
              ]
            },
            {
              "id": "CVE-2025-59249",
              "title": "Exchange EoP — Weak Authentication (Oct 2025)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Weak authentication mechanism enabling privilege escalation. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59249"
              ]
            },
            {
              "id": "CVE-2026-69355",
              "title": "Exchange RCE — Authenticated (Sep 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Authenticated attacker can execute arbitrary code on the Exchange server. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69355"
              ]
            },
            {
              "id": "CVE-2026-62913",
              "title": "Exchange RCE — Heap Buffer Overflow (Aug 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Heap buffer overflow permitting authenticated remote code execution. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62913"
              ]
            },
            {
              "id": "CVE-2026-55005",
              "title": "Exchange RCE — Heap Buffer Overflow (Jul 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Heap-based buffer overflow enabling authenticated remote code execution. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55005"
              ]
            },
            {
              "id": "CVE-2026-45504",
              "title": "Exchange EoP — SSRF (Jun 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "SSRF vulnerability enabling authenticated privilege escalation. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45504"
              ]
            },
            {
              "id": "CVE-2025-53782",
              "title": "Exchange EoP — Authentication Algorithm (Oct 2025)",
              "cvss": 8.4,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Incorrect implementation of authentication algorithm allowing an unauthorized attacker to elevate privileges locally. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53782"
              ]
            },
            {
              "id": "CVE-2026-69380",
              "title": "Exchange EoP — Missing Authorization (Sep 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Missing authorization flaw enabling low-privilege users to read and send mail as other Exchange users. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69380"
              ]
            },
            {
              "id": "CVE-2026-55007",
              "title": "Exchange RCE (Jul/Sep 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Remote code execution vulnerability. Partially addressed in July 2026 SU and fully patched in September 2026 SU. Does not affect Exchange 2016.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55007"
              ]
            },
            {
              "id": "CVE-2026-42897",
              "title": "Exchange XSS / Information Disclosure — Exploited (Jun 2026)",
              "cvss": 8.1,
              "severity": "critical",
              "type": "Information Disclosure / XSS",
              "auth_required": false,
              "exploited_in_wild": true,
              "description": "XSS flaw permitting unauthenticated remote spoofing and information disclosure. Exploited in the wild before patch release. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42897"
              ]
            },
            {
              "id": "CVE-2026-47631",
              "title": "Exchange Spoofing — Input Sanitization (Jun 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Input sanitization flaw enabling unauthenticated spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-47631"
              ]
            },
            {
              "id": "CVE-2026-45503",
              "title": "Exchange Information Disclosure — Authorization Flaw (Jun 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Authorization flaw exposing sensitive Exchange information. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45503"
              ]
            },
            {
              "id": "CVE-2026-62911",
              "title": "Exchange EoP — Replay Authentication Bypass (Aug 2026)",
              "cvss": 8.0,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Replay-based authentication bypass letting an authenticated attacker escalate privileges. Nearly 22,000 exposed servers identified as vulnerable. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62911"
              ]
            },
            {
              "id": "CVE-2026-55009",
              "title": "Exchange EoP — Unsafe Deserialization (Jul/Aug 2026)",
              "cvss": 7.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Unsafe deserialization enabling local privilege elevation. Disclosed July 2026, fully fixed in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55009"
              ]
            },
            {
              "id": "CVE-2026-55006",
              "title": "Exchange EoP — Access Controls (Jul 2026)",
              "cvss": 7.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Overly coarse access controls enabling privilege escalation. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55006"
              ]
            },
            {
              "id": "CVE-2025-33051",
              "title": "Exchange Information Disclosure (Aug 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Exposure of sensitive Exchange information to an unauthorized actor. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33051"
              ]
            },
            {
              "id": "CVE-2025-59248",
              "title": "Exchange Spoofing (Oct 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Input validation flaw permitting unauthorized spoofing. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59248"
              ]
            },
            {
              "id": "CVE-2025-64666",
              "title": "Exchange EoP — Input Validation (Dec 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Improper input validation allowing an authorized attacker to elevate privileges. Patched in December 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64666"
              ]
            },
            {
              "id": "CVE-2026-69378",
              "title": "Exchange DoS (Sep 2026)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Denial of Service",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Allows an attacker to crash the Exchange service. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69378"
              ]
            },
            {
              "id": "CVE-2026-45583",
              "title": "Exchange RCE — Code Injection (Jun 2026)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Code injection flaw permitting unauthenticated remote code execution. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45583"
              ]
            },
            {
              "id": "CVE-2026-62914",
              "title": "Exchange Spoofing — XSS (Aug 2026)",
              "cvss": 7.3,
              "severity": "high",
              "type": "Spoofing / XSS",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Cross-site scripting enabling content spoofing by authenticated users. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62914"
              ]
            },
            {
              "id": "CVE-2026-62910",
              "title": "Exchange EoP — Resource Injection CRITICAL (Aug 2026)",
              "cvss": 7.2,
              "severity": "critical",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Resource injection enabling privilege escalation. Classified critical despite CVSS 7.2 due to attack surface. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62910"
              ]
            },
            {
              "id": "CVE-2025-25005",
              "title": "Exchange Tampering (Aug 2025)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Tampering",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Input validation flaw allowing an authenticated attacker to tamper with Exchange data. Patched in August 2025 SU (first SE SU1, CU15 SU0).",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25005"
              ]
            },
            {
              "id": "CVE-2026-21527",
              "title": "Exchange Spoofing (Feb 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "UI misrepresentation enabling user spoofing by authenticated attackers. Patched in February 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-21527"
              ]
            },
            {
              "id": "CVE-2026-69361",
              "title": "Exchange Spoofing — SSRF (Sep 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Server-side request forgery issue enabling spoofing over the network. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69361"
              ]
            },
            {
              "id": "CVE-2026-69375",
              "title": "Exchange Tampering (Sep 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Tampering",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Enables unauthorized data manipulation in Exchange. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69375"
              ]
            },
            {
              "id": "CVE-2026-65813",
              "title": "Exchange EoP — SSRF (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Server-side request forgery flaw letting an authenticated attacker gain higher privileges remotely. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-65813"
              ]
            },
            {
              "id": "CVE-2026-62915",
              "title": "Exchange Security Feature Bypass (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Security Feature Bypass",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Authorization bypass allowing logged-in users to sidestep Exchange security controls. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62915"
              ]
            },
            {
              "id": "CVE-2026-62912",
              "title": "Exchange DoS — Unsafe Deserialization (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Denial of Service",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Unsafe deserialization allowing service crashes. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62912"
              ]
            },
            {
              "id": "CVE-2026-45501",
              "title": "Exchange Spoofing — SSRF (Jun 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "SSRF vulnerability allowing content spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45501"
              ]
            },
            {
              "id": "CVE-2026-45500",
              "title": "Exchange Spoofing — Output Encoding (Jun 2026)",
              "cvss": 6.1,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Output encoding flaw enabling unauthenticated spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45500"
              ]
            },
            {
              "id": "CVE-2026-69382",
              "title": "Exchange Information Disclosure (Sep 2026)",
              "cvss": 5.9,
              "severity": "medium",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Permits disclosure of restricted Exchange information. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69382"
              ]
            },
            {
              "id": "CVE-2025-25006",
              "title": "Exchange Spoofing (Aug 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Special element handling flaw enabling spoofing of Exchange content. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25006"
              ]
            },
            {
              "id": "CVE-2025-25007",
              "title": "Exchange Spoofing (Aug 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Input validation flaw permitting unauthorized spoofing of Exchange email content. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25007"
              ]
            },
            {
              "id": "CVE-2025-64667",
              "title": "Exchange Spoofing — UI Misrepresentation (Dec 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "UI misrepresentation enabling spoofing of Exchange content. Patched in December 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64667"
              ]
            },
            {
              "id": "CVE-2026-45502",
              "title": "Exchange Information Disclosure — SSRF (Jun 2026)",
              "cvss": 5.0,
              "severity": "medium",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Lower-severity SSRF enabling information leakage from Exchange. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45502"
              ]
            }
          ]
        }
      },
      {
        "source": "auth_endpoint",
        "url": "https://wmail.azercell.com/mapi/",
        "path": "/mapi/",
        "http_status": 401,
        "auth_required": true,
        "auth_type": "Negotiate",
        "www_authenticate": "Negotiate",
        "disclosures": {
          "X-OWA-Version": "15.2.2562.17",
          "X-FEServer": "MBX19-N01",
          "WWW-Authenticate": "Negotiate",
          "Set-Cookie": "TS0160ab2a=01db3e592e9d9b99e4cfb4a24de53fa58fd64ca890678669cf675aaa6c1e9f9f60dfbe1647c10f719ae1378a480268f57c91dee0a0; Path=/; Domain=.wmail.azercell.com",
          "ntlm:target_name": "AZERCELL",
          "ntlm:nb_domain_name": "AZERCELL",
          "ntlm:nb_computer_name": "MBX19-N01",
          "ntlm:dns_domain_name": "azercell.com",
          "ntlm:dns_computer_name": "MBX19-N01.azercell.com",
          "ntlm:dns_tree_name": "azercell.com"
        },
        "severity": "high",
        "version_info": {
          "label": "Exchange SE RTM",
          "build": "15.2.2562.17",
          "release_date": "2025-07-08",
          "kb": "KB5047155",
          "is_latest": false,
          "versions_behind": 10,
          "days_old": 457,
          "cve_count": 38,
          "cves": [
            {
              "id": "CVE-2026-55008",
              "title": "Exchange Spoofing — XSS CRITICAL (Jul 2026)",
              "cvss": 9.6,
              "severity": "critical",
              "type": "Spoofing / XSS",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "XSS allowing unauthenticated spoofing with critical CVSS score of 9.6. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55008"
              ]
            },
            {
              "id": "CVE-2026-69356",
              "title": "Exchange Spoofing — Sender Impersonation (Sep 2026)",
              "cvss": 9.3,
              "severity": "critical",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Allows an attacker to impersonate a different sender in Exchange emails. CVSS 9.3. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69356"
              ]
            },
            {
              "id": "CVE-2026-69641",
              "title": "Exchange EoP — High Severity (Sep 2026)",
              "cvss": 9.1,
              "severity": "critical",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Permits attackers to obtain elevated privileges within Exchange. CVSS 9.1. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69641"
              ]
            },
            {
              "id": "CVE-2025-59249",
              "title": "Exchange EoP — Weak Authentication (Oct 2025)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Weak authentication mechanism enabling privilege escalation. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59249"
              ]
            },
            {
              "id": "CVE-2026-69355",
              "title": "Exchange RCE — Authenticated (Sep 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Authenticated attacker can execute arbitrary code on the Exchange server. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69355"
              ]
            },
            {
              "id": "CVE-2026-62913",
              "title": "Exchange RCE — Heap Buffer Overflow (Aug 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Heap buffer overflow permitting authenticated remote code execution. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62913"
              ]
            },
            {
              "id": "CVE-2026-55005",
              "title": "Exchange RCE — Heap Buffer Overflow (Jul 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Heap-based buffer overflow enabling authenticated remote code execution. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55005"
              ]
            },
            {
              "id": "CVE-2026-45504",
              "title": "Exchange EoP — SSRF (Jun 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "SSRF vulnerability enabling authenticated privilege escalation. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45504"
              ]
            },
            {
              "id": "CVE-2025-53782",
              "title": "Exchange EoP — Authentication Algorithm (Oct 2025)",
              "cvss": 8.4,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Incorrect implementation of authentication algorithm allowing an unauthorized attacker to elevate privileges locally. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53782"
              ]
            },
            {
              "id": "CVE-2026-69380",
              "title": "Exchange EoP — Missing Authorization (Sep 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Missing authorization flaw enabling low-privilege users to read and send mail as other Exchange users. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69380"
              ]
            },
            {
              "id": "CVE-2026-55007",
              "title": "Exchange RCE (Jul/Sep 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Remote code execution vulnerability. Partially addressed in July 2026 SU and fully patched in September 2026 SU. Does not affect Exchange 2016.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55007"
              ]
            },
            {
              "id": "CVE-2026-42897",
              "title": "Exchange XSS / Information Disclosure — Exploited (Jun 2026)",
              "cvss": 8.1,
              "severity": "critical",
              "type": "Information Disclosure / XSS",
              "auth_required": false,
              "exploited_in_wild": true,
              "description": "XSS flaw permitting unauthenticated remote spoofing and information disclosure. Exploited in the wild before patch release. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42897"
              ]
            },
            {
              "id": "CVE-2026-47631",
              "title": "Exchange Spoofing — Input Sanitization (Jun 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Input sanitization flaw enabling unauthenticated spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-47631"
              ]
            },
            {
              "id": "CVE-2026-45503",
              "title": "Exchange Information Disclosure — Authorization Flaw (Jun 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Authorization flaw exposing sensitive Exchange information. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45503"
              ]
            },
            {
              "id": "CVE-2026-62911",
              "title": "Exchange EoP — Replay Authentication Bypass (Aug 2026)",
              "cvss": 8.0,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Replay-based authentication bypass letting an authenticated attacker escalate privileges. Nearly 22,000 exposed servers identified as vulnerable. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62911"
              ]
            },
            {
              "id": "CVE-2026-55009",
              "title": "Exchange EoP — Unsafe Deserialization (Jul/Aug 2026)",
              "cvss": 7.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Unsafe deserialization enabling local privilege elevation. Disclosed July 2026, fully fixed in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55009"
              ]
            },
            {
              "id": "CVE-2026-55006",
              "title": "Exchange EoP — Access Controls (Jul 2026)",
              "cvss": 7.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Overly coarse access controls enabling privilege escalation. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55006"
              ]
            },
            {
              "id": "CVE-2025-33051",
              "title": "Exchange Information Disclosure (Aug 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Exposure of sensitive Exchange information to an unauthorized actor. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33051"
              ]
            },
            {
              "id": "CVE-2025-59248",
              "title": "Exchange Spoofing (Oct 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Input validation flaw permitting unauthorized spoofing. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59248"
              ]
            },
            {
              "id": "CVE-2025-64666",
              "title": "Exchange EoP — Input Validation (Dec 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Improper input validation allowing an authorized attacker to elevate privileges. Patched in December 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64666"
              ]
            },
            {
              "id": "CVE-2026-69378",
              "title": "Exchange DoS (Sep 2026)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Denial of Service",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Allows an attacker to crash the Exchange service. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69378"
              ]
            },
            {
              "id": "CVE-2026-45583",
              "title": "Exchange RCE — Code Injection (Jun 2026)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Code injection flaw permitting unauthenticated remote code execution. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45583"
              ]
            },
            {
              "id": "CVE-2026-62914",
              "title": "Exchange Spoofing — XSS (Aug 2026)",
              "cvss": 7.3,
              "severity": "high",
              "type": "Spoofing / XSS",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Cross-site scripting enabling content spoofing by authenticated users. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62914"
              ]
            },
            {
              "id": "CVE-2026-62910",
              "title": "Exchange EoP — Resource Injection CRITICAL (Aug 2026)",
              "cvss": 7.2,
              "severity": "critical",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Resource injection enabling privilege escalation. Classified critical despite CVSS 7.2 due to attack surface. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62910"
              ]
            },
            {
              "id": "CVE-2025-25005",
              "title": "Exchange Tampering (Aug 2025)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Tampering",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Input validation flaw allowing an authenticated attacker to tamper with Exchange data. Patched in August 2025 SU (first SE SU1, CU15 SU0).",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25005"
              ]
            },
            {
              "id": "CVE-2026-21527",
              "title": "Exchange Spoofing (Feb 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "UI misrepresentation enabling user spoofing by authenticated attackers. Patched in February 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-21527"
              ]
            },
            {
              "id": "CVE-2026-69361",
              "title": "Exchange Spoofing — SSRF (Sep 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Server-side request forgery issue enabling spoofing over the network. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69361"
              ]
            },
            {
              "id": "CVE-2026-69375",
              "title": "Exchange Tampering (Sep 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Tampering",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Enables unauthorized data manipulation in Exchange. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69375"
              ]
            },
            {
              "id": "CVE-2026-65813",
              "title": "Exchange EoP — SSRF (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Server-side request forgery flaw letting an authenticated attacker gain higher privileges remotely. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-65813"
              ]
            },
            {
              "id": "CVE-2026-62915",
              "title": "Exchange Security Feature Bypass (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Security Feature Bypass",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Authorization bypass allowing logged-in users to sidestep Exchange security controls. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62915"
              ]
            },
            {
              "id": "CVE-2026-62912",
              "title": "Exchange DoS — Unsafe Deserialization (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Denial of Service",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Unsafe deserialization allowing service crashes. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62912"
              ]
            },
            {
              "id": "CVE-2026-45501",
              "title": "Exchange Spoofing — SSRF (Jun 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "SSRF vulnerability allowing content spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45501"
              ]
            },
            {
              "id": "CVE-2026-45500",
              "title": "Exchange Spoofing — Output Encoding (Jun 2026)",
              "cvss": 6.1,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Output encoding flaw enabling unauthenticated spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45500"
              ]
            },
            {
              "id": "CVE-2026-69382",
              "title": "Exchange Information Disclosure (Sep 2026)",
              "cvss": 5.9,
              "severity": "medium",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Permits disclosure of restricted Exchange information. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69382"
              ]
            },
            {
              "id": "CVE-2025-25006",
              "title": "Exchange Spoofing (Aug 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Special element handling flaw enabling spoofing of Exchange content. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25006"
              ]
            },
            {
              "id": "CVE-2025-25007",
              "title": "Exchange Spoofing (Aug 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Input validation flaw permitting unauthorized spoofing of Exchange email content. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25007"
              ]
            },
            {
              "id": "CVE-2025-64667",
              "title": "Exchange Spoofing — UI Misrepresentation (Dec 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "UI misrepresentation enabling spoofing of Exchange content. Patched in December 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64667"
              ]
            },
            {
              "id": "CVE-2026-45502",
              "title": "Exchange Information Disclosure — SSRF (Jun 2026)",
              "cvss": 5.0,
              "severity": "medium",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Lower-severity SSRF enabling information leakage from Exchange. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45502"
              ]
            }
          ]
        }
      },
      {
        "source": "auth_endpoint",
        "url": "https://wmail.azercell.com/Microsoft-Server-ActiveSync",
        "path": "/Microsoft-Server-ActiveSync",
        "http_status": 401,
        "auth_required": true,
        "auth_type": "Basic",
        "www_authenticate": "Basic realm=\"wmail.azercell.com\"",
        "disclosures": {
          "X-OWA-Version": "15.2.2562.17",
          "X-FEServer": "MBX19-N01",
          "WWW-Authenticate": "Basic realm=\"wmail.azercell.com\"",
          "Set-Cookie": "TS0160ab2a=01db3e592e85d0057933d403c159fc9104e97a262f7ebbc0eb7c545c0765b0705eadee6f60037c4bc33708776036b30430acc89bde; Path=/; Domain=.wmail.azercell.com"
        },
        "severity": "high",
        "version_info": {
          "label": "Exchange SE RTM",
          "build": "15.2.2562.17",
          "release_date": "2025-07-08",
          "kb": "KB5047155",
          "is_latest": false,
          "versions_behind": 10,
          "days_old": 457,
          "cve_count": 38,
          "cves": [
            {
              "id": "CVE-2026-55008",
              "title": "Exchange Spoofing — XSS CRITICAL (Jul 2026)",
              "cvss": 9.6,
              "severity": "critical",
              "type": "Spoofing / XSS",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "XSS allowing unauthenticated spoofing with critical CVSS score of 9.6. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55008"
              ]
            },
            {
              "id": "CVE-2026-69356",
              "title": "Exchange Spoofing — Sender Impersonation (Sep 2026)",
              "cvss": 9.3,
              "severity": "critical",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Allows an attacker to impersonate a different sender in Exchange emails. CVSS 9.3. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69356"
              ]
            },
            {
              "id": "CVE-2026-69641",
              "title": "Exchange EoP — High Severity (Sep 2026)",
              "cvss": 9.1,
              "severity": "critical",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Permits attackers to obtain elevated privileges within Exchange. CVSS 9.1. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69641"
              ]
            },
            {
              "id": "CVE-2025-59249",
              "title": "Exchange EoP — Weak Authentication (Oct 2025)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Weak authentication mechanism enabling privilege escalation. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59249"
              ]
            },
            {
              "id": "CVE-2026-69355",
              "title": "Exchange RCE — Authenticated (Sep 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Authenticated attacker can execute arbitrary code on the Exchange server. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69355"
              ]
            },
            {
              "id": "CVE-2026-62913",
              "title": "Exchange RCE — Heap Buffer Overflow (Aug 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Heap buffer overflow permitting authenticated remote code execution. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62913"
              ]
            },
            {
              "id": "CVE-2026-55005",
              "title": "Exchange RCE — Heap Buffer Overflow (Jul 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Heap-based buffer overflow enabling authenticated remote code execution. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55005"
              ]
            },
            {
              "id": "CVE-2026-45504",
              "title": "Exchange EoP — SSRF (Jun 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "SSRF vulnerability enabling authenticated privilege escalation. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45504"
              ]
            },
            {
              "id": "CVE-2025-53782",
              "title": "Exchange EoP — Authentication Algorithm (Oct 2025)",
              "cvss": 8.4,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Incorrect implementation of authentication algorithm allowing an unauthorized attacker to elevate privileges locally. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53782"
              ]
            },
            {
              "id": "CVE-2026-69380",
              "title": "Exchange EoP — Missing Authorization (Sep 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Missing authorization flaw enabling low-privilege users to read and send mail as other Exchange users. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69380"
              ]
            },
            {
              "id": "CVE-2026-55007",
              "title": "Exchange RCE (Jul/Sep 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Remote code execution vulnerability. Partially addressed in July 2026 SU and fully patched in September 2026 SU. Does not affect Exchange 2016.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55007"
              ]
            },
            {
              "id": "CVE-2026-42897",
              "title": "Exchange XSS / Information Disclosure — Exploited (Jun 2026)",
              "cvss": 8.1,
              "severity": "critical",
              "type": "Information Disclosure / XSS",
              "auth_required": false,
              "exploited_in_wild": true,
              "description": "XSS flaw permitting unauthenticated remote spoofing and information disclosure. Exploited in the wild before patch release. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42897"
              ]
            },
            {
              "id": "CVE-2026-47631",
              "title": "Exchange Spoofing — Input Sanitization (Jun 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Input sanitization flaw enabling unauthenticated spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-47631"
              ]
            },
            {
              "id": "CVE-2026-45503",
              "title": "Exchange Information Disclosure — Authorization Flaw (Jun 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Authorization flaw exposing sensitive Exchange information. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45503"
              ]
            },
            {
              "id": "CVE-2026-62911",
              "title": "Exchange EoP — Replay Authentication Bypass (Aug 2026)",
              "cvss": 8.0,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Replay-based authentication bypass letting an authenticated attacker escalate privileges. Nearly 22,000 exposed servers identified as vulnerable. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62911"
              ]
            },
            {
              "id": "CVE-2026-55009",
              "title": "Exchange EoP — Unsafe Deserialization (Jul/Aug 2026)",
              "cvss": 7.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Unsafe deserialization enabling local privilege elevation. Disclosed July 2026, fully fixed in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55009"
              ]
            },
            {
              "id": "CVE-2026-55006",
              "title": "Exchange EoP — Access Controls (Jul 2026)",
              "cvss": 7.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Overly coarse access controls enabling privilege escalation. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55006"
              ]
            },
            {
              "id": "CVE-2025-33051",
              "title": "Exchange Information Disclosure (Aug 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Exposure of sensitive Exchange information to an unauthorized actor. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33051"
              ]
            },
            {
              "id": "CVE-2025-59248",
              "title": "Exchange Spoofing (Oct 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Input validation flaw permitting unauthorized spoofing. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59248"
              ]
            },
            {
              "id": "CVE-2025-64666",
              "title": "Exchange EoP — Input Validation (Dec 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Improper input validation allowing an authorized attacker to elevate privileges. Patched in December 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64666"
              ]
            },
            {
              "id": "CVE-2026-69378",
              "title": "Exchange DoS (Sep 2026)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Denial of Service",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Allows an attacker to crash the Exchange service. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69378"
              ]
            },
            {
              "id": "CVE-2026-45583",
              "title": "Exchange RCE — Code Injection (Jun 2026)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Code injection flaw permitting unauthenticated remote code execution. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45583"
              ]
            },
            {
              "id": "CVE-2026-62914",
              "title": "Exchange Spoofing — XSS (Aug 2026)",
              "cvss": 7.3,
              "severity": "high",
              "type": "Spoofing / XSS",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Cross-site scripting enabling content spoofing by authenticated users. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62914"
              ]
            },
            {
              "id": "CVE-2026-62910",
              "title": "Exchange EoP — Resource Injection CRITICAL (Aug 2026)",
              "cvss": 7.2,
              "severity": "critical",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Resource injection enabling privilege escalation. Classified critical despite CVSS 7.2 due to attack surface. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62910"
              ]
            },
            {
              "id": "CVE-2025-25005",
              "title": "Exchange Tampering (Aug 2025)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Tampering",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Input validation flaw allowing an authenticated attacker to tamper with Exchange data. Patched in August 2025 SU (first SE SU1, CU15 SU0).",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25005"
              ]
            },
            {
              "id": "CVE-2026-21527",
              "title": "Exchange Spoofing (Feb 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "UI misrepresentation enabling user spoofing by authenticated attackers. Patched in February 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-21527"
              ]
            },
            {
              "id": "CVE-2026-69361",
              "title": "Exchange Spoofing — SSRF (Sep 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Server-side request forgery issue enabling spoofing over the network. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69361"
              ]
            },
            {
              "id": "CVE-2026-69375",
              "title": "Exchange Tampering (Sep 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Tampering",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Enables unauthorized data manipulation in Exchange. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69375"
              ]
            },
            {
              "id": "CVE-2026-65813",
              "title": "Exchange EoP — SSRF (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Server-side request forgery flaw letting an authenticated attacker gain higher privileges remotely. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-65813"
              ]
            },
            {
              "id": "CVE-2026-62915",
              "title": "Exchange Security Feature Bypass (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Security Feature Bypass",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Authorization bypass allowing logged-in users to sidestep Exchange security controls. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62915"
              ]
            },
            {
              "id": "CVE-2026-62912",
              "title": "Exchange DoS — Unsafe Deserialization (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Denial of Service",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Unsafe deserialization allowing service crashes. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62912"
              ]
            },
            {
              "id": "CVE-2026-45501",
              "title": "Exchange Spoofing — SSRF (Jun 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "SSRF vulnerability allowing content spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45501"
              ]
            },
            {
              "id": "CVE-2026-45500",
              "title": "Exchange Spoofing — Output Encoding (Jun 2026)",
              "cvss": 6.1,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Output encoding flaw enabling unauthenticated spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45500"
              ]
            },
            {
              "id": "CVE-2026-69382",
              "title": "Exchange Information Disclosure (Sep 2026)",
              "cvss": 5.9,
              "severity": "medium",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Permits disclosure of restricted Exchange information. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69382"
              ]
            },
            {
              "id": "CVE-2025-25006",
              "title": "Exchange Spoofing (Aug 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Special element handling flaw enabling spoofing of Exchange content. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25006"
              ]
            },
            {
              "id": "CVE-2025-25007",
              "title": "Exchange Spoofing (Aug 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Input validation flaw permitting unauthorized spoofing of Exchange email content. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25007"
              ]
            },
            {
              "id": "CVE-2025-64667",
              "title": "Exchange Spoofing — UI Misrepresentation (Dec 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "UI misrepresentation enabling spoofing of Exchange content. Patched in December 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64667"
              ]
            },
            {
              "id": "CVE-2026-45502",
              "title": "Exchange Information Disclosure — SSRF (Jun 2026)",
              "cvss": 5.0,
              "severity": "medium",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Lower-severity SSRF enabling information leakage from Exchange. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45502"
              ]
            }
          ]
        }
      },
      {
        "source": "owa_fingerprint",
        "url": "https://wmail.azercell.com/owa/",
        "path": "/owa/",
        "http_status": 200,
        "disclosures": {
          "body:owa_build_label": "15.2.2562"
        },
        "severity": "low",
        "version_info": {}
      },
      {
        "source": "ediscovery_manifest",
        "url": "https://wmail.azercell.com/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application",
        "path": "/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application",
        "http_status": 200,
        "auth_required": false,
        "exchange_build": "15.2.2562.17",
        "assembly_name": "microsoft.exchange.ediscovery.exporttool.application",
        "disclosures": {
          "ediscovery:exchange_build": "15.2.2562.17",
          "ediscovery:assembly_name": "microsoft.exchange.ediscovery.exporttool.application",
          "X-FEServer": "MBX19-N01",
          "X-BEServer": "MBX19-N02",
          "X-DiagInfo": "MBX19-N02",
          "X-CalculatedBETarget": "mbx19-n02.azercell.com",
          "Set-Cookie": "TS0160ab2a=01db3e592e857b1b254d304f5d0630bea28891fed54c8e6ad15fa12aeaa04aced0d3c79acd5daf9d8945ae5c31ec0edf615b154518; Path=/; Domain=.wmail.azercell.com"
        },
        "severity": "high",
        "version_info": {
          "label": "Exchange SE RTM",
          "build": "15.2.2562.17",
          "release_date": "2025-07-08",
          "kb": "KB5047155",
          "is_latest": false,
          "versions_behind": 10,
          "days_old": 457,
          "cve_count": 38,
          "cves": [
            {
              "id": "CVE-2026-55008",
              "title": "Exchange Spoofing — XSS CRITICAL (Jul 2026)",
              "cvss": 9.6,
              "severity": "critical",
              "type": "Spoofing / XSS",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "XSS allowing unauthenticated spoofing with critical CVSS score of 9.6. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55008"
              ]
            },
            {
              "id": "CVE-2026-69356",
              "title": "Exchange Spoofing — Sender Impersonation (Sep 2026)",
              "cvss": 9.3,
              "severity": "critical",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Allows an attacker to impersonate a different sender in Exchange emails. CVSS 9.3. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69356"
              ]
            },
            {
              "id": "CVE-2026-69641",
              "title": "Exchange EoP — High Severity (Sep 2026)",
              "cvss": 9.1,
              "severity": "critical",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Permits attackers to obtain elevated privileges within Exchange. CVSS 9.1. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69641"
              ]
            },
            {
              "id": "CVE-2025-59249",
              "title": "Exchange EoP — Weak Authentication (Oct 2025)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Weak authentication mechanism enabling privilege escalation. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59249"
              ]
            },
            {
              "id": "CVE-2026-69355",
              "title": "Exchange RCE — Authenticated (Sep 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Authenticated attacker can execute arbitrary code on the Exchange server. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69355"
              ]
            },
            {
              "id": "CVE-2026-62913",
              "title": "Exchange RCE — Heap Buffer Overflow (Aug 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Heap buffer overflow permitting authenticated remote code execution. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62913"
              ]
            },
            {
              "id": "CVE-2026-55005",
              "title": "Exchange RCE — Heap Buffer Overflow (Jul 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Heap-based buffer overflow enabling authenticated remote code execution. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55005"
              ]
            },
            {
              "id": "CVE-2026-45504",
              "title": "Exchange EoP — SSRF (Jun 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "SSRF vulnerability enabling authenticated privilege escalation. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45504"
              ]
            },
            {
              "id": "CVE-2025-53782",
              "title": "Exchange EoP — Authentication Algorithm (Oct 2025)",
              "cvss": 8.4,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Incorrect implementation of authentication algorithm allowing an unauthorized attacker to elevate privileges locally. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53782"
              ]
            },
            {
              "id": "CVE-2026-69380",
              "title": "Exchange EoP — Missing Authorization (Sep 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Missing authorization flaw enabling low-privilege users to read and send mail as other Exchange users. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69380"
              ]
            },
            {
              "id": "CVE-2026-55007",
              "title": "Exchange RCE (Jul/Sep 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Remote code execution vulnerability. Partially addressed in July 2026 SU and fully patched in September 2026 SU. Does not affect Exchange 2016.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55007"
              ]
            },
            {
              "id": "CVE-2026-42897",
              "title": "Exchange XSS / Information Disclosure — Exploited (Jun 2026)",
              "cvss": 8.1,
              "severity": "critical",
              "type": "Information Disclosure / XSS",
              "auth_required": false,
              "exploited_in_wild": true,
              "description": "XSS flaw permitting unauthenticated remote spoofing and information disclosure. Exploited in the wild before patch release. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42897"
              ]
            },
            {
              "id": "CVE-2026-47631",
              "title": "Exchange Spoofing — Input Sanitization (Jun 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Input sanitization flaw enabling unauthenticated spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-47631"
              ]
            },
            {
              "id": "CVE-2026-45503",
              "title": "Exchange Information Disclosure — Authorization Flaw (Jun 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Authorization flaw exposing sensitive Exchange information. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45503"
              ]
            },
            {
              "id": "CVE-2026-62911",
              "title": "Exchange EoP — Replay Authentication Bypass (Aug 2026)",
              "cvss": 8.0,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Replay-based authentication bypass letting an authenticated attacker escalate privileges. Nearly 22,000 exposed servers identified as vulnerable. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62911"
              ]
            },
            {
              "id": "CVE-2026-55009",
              "title": "Exchange EoP — Unsafe Deserialization (Jul/Aug 2026)",
              "cvss": 7.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Unsafe deserialization enabling local privilege elevation. Disclosed July 2026, fully fixed in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55009"
              ]
            },
            {
              "id": "CVE-2026-55006",
              "title": "Exchange EoP — Access Controls (Jul 2026)",
              "cvss": 7.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Overly coarse access controls enabling privilege escalation. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55006"
              ]
            },
            {
              "id": "CVE-2025-33051",
              "title": "Exchange Information Disclosure (Aug 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Exposure of sensitive Exchange information to an unauthorized actor. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33051"
              ]
            },
            {
              "id": "CVE-2025-59248",
              "title": "Exchange Spoofing (Oct 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Input validation flaw permitting unauthorized spoofing. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59248"
              ]
            },
            {
              "id": "CVE-2025-64666",
              "title": "Exchange EoP — Input Validation (Dec 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Improper input validation allowing an authorized attacker to elevate privileges. Patched in December 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64666"
              ]
            },
            {
              "id": "CVE-2026-69378",
              "title": "Exchange DoS (Sep 2026)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Denial of Service",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Allows an attacker to crash the Exchange service. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69378"
              ]
            },
            {
              "id": "CVE-2026-45583",
              "title": "Exchange RCE — Code Injection (Jun 2026)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Code injection flaw permitting unauthenticated remote code execution. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45583"
              ]
            },
            {
              "id": "CVE-2026-62914",
              "title": "Exchange Spoofing — XSS (Aug 2026)",
              "cvss": 7.3,
              "severity": "high",
              "type": "Spoofing / XSS",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Cross-site scripting enabling content spoofing by authenticated users. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62914"
              ]
            },
            {
              "id": "CVE-2026-62910",
              "title": "Exchange EoP — Resource Injection CRITICAL (Aug 2026)",
              "cvss": 7.2,
              "severity": "critical",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Resource injection enabling privilege escalation. Classified critical despite CVSS 7.2 due to attack surface. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62910"
              ]
            },
            {
              "id": "CVE-2025-25005",
              "title": "Exchange Tampering (Aug 2025)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Tampering",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Input validation flaw allowing an authenticated attacker to tamper with Exchange data. Patched in August 2025 SU (first SE SU1, CU15 SU0).",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25005"
              ]
            },
            {
              "id": "CVE-2026-21527",
              "title": "Exchange Spoofing (Feb 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "UI misrepresentation enabling user spoofing by authenticated attackers. Patched in February 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-21527"
              ]
            },
            {
              "id": "CVE-2026-69361",
              "title": "Exchange Spoofing — SSRF (Sep 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Server-side request forgery issue enabling spoofing over the network. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69361"
              ]
            },
            {
              "id": "CVE-2026-69375",
              "title": "Exchange Tampering (Sep 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Tampering",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Enables unauthorized data manipulation in Exchange. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69375"
              ]
            },
            {
              "id": "CVE-2026-65813",
              "title": "Exchange EoP — SSRF (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Server-side request forgery flaw letting an authenticated attacker gain higher privileges remotely. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-65813"
              ]
            },
            {
              "id": "CVE-2026-62915",
              "title": "Exchange Security Feature Bypass (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Security Feature Bypass",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Authorization bypass allowing logged-in users to sidestep Exchange security controls. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62915"
              ]
            },
            {
              "id": "CVE-2026-62912",
              "title": "Exchange DoS — Unsafe Deserialization (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Denial of Service",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Unsafe deserialization allowing service crashes. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62912"
              ]
            },
            {
              "id": "CVE-2026-45501",
              "title": "Exchange Spoofing — SSRF (Jun 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "SSRF vulnerability allowing content spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45501"
              ]
            },
            {
              "id": "CVE-2026-45500",
              "title": "Exchange Spoofing — Output Encoding (Jun 2026)",
              "cvss": 6.1,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Output encoding flaw enabling unauthenticated spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45500"
              ]
            },
            {
              "id": "CVE-2026-69382",
              "title": "Exchange Information Disclosure (Sep 2026)",
              "cvss": 5.9,
              "severity": "medium",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Permits disclosure of restricted Exchange information. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69382"
              ]
            },
            {
              "id": "CVE-2025-25006",
              "title": "Exchange Spoofing (Aug 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Special element handling flaw enabling spoofing of Exchange content. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25006"
              ]
            },
            {
              "id": "CVE-2025-25007",
              "title": "Exchange Spoofing (Aug 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Input validation flaw permitting unauthorized spoofing of Exchange email content. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25007"
              ]
            },
            {
              "id": "CVE-2025-64667",
              "title": "Exchange Spoofing — UI Misrepresentation (Dec 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "UI misrepresentation enabling spoofing of Exchange content. Patched in December 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64667"
              ]
            },
            {
              "id": "CVE-2026-45502",
              "title": "Exchange Information Disclosure — SSRF (Jun 2026)",
              "cvss": 5.0,
              "severity": "medium",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Lower-severity SSRF enabling information leakage from Exchange. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45502"
              ]
            }
          ]
        }
      },
      {
        "source": "auth_endpoint",
        "url": "https://wmail.azercell.com/OAB/",
        "path": "/OAB/",
        "http_status": 401,
        "auth_required": true,
        "auth_type": "Negotiate",
        "www_authenticate": "Negotiate",
        "disclosures": {
          "X-OWA-Version": "15.2.2562.17",
          "X-FEServer": "MBX19-N01",
          "WWW-Authenticate": "Negotiate",
          "Set-Cookie": "TS0160ab2a=01db3e592eaa2c74ae2889bc0bf89d5a7466ae401b6b503ad24f1e53548b206a9bd9e8fe76176bcd9763f7912b43dc3cd1f17a69d6; Path=/; Domain=.wmail.azercell.com",
          "ntlm:target_name": "AZERCELL",
          "ntlm:nb_domain_name": "AZERCELL",
          "ntlm:nb_computer_name": "MBX19-N01",
          "ntlm:dns_domain_name": "azercell.com",
          "ntlm:dns_computer_name": "MBX19-N01.azercell.com",
          "ntlm:dns_tree_name": "azercell.com"
        },
        "severity": "high",
        "version_info": {
          "label": "Exchange SE RTM",
          "build": "15.2.2562.17",
          "release_date": "2025-07-08",
          "kb": "KB5047155",
          "is_latest": false,
          "versions_behind": 10,
          "days_old": 457,
          "cve_count": 38,
          "cves": [
            {
              "id": "CVE-2026-55008",
              "title": "Exchange Spoofing — XSS CRITICAL (Jul 2026)",
              "cvss": 9.6,
              "severity": "critical",
              "type": "Spoofing / XSS",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "XSS allowing unauthenticated spoofing with critical CVSS score of 9.6. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55008"
              ]
            },
            {
              "id": "CVE-2026-69356",
              "title": "Exchange Spoofing — Sender Impersonation (Sep 2026)",
              "cvss": 9.3,
              "severity": "critical",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Allows an attacker to impersonate a different sender in Exchange emails. CVSS 9.3. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69356"
              ]
            },
            {
              "id": "CVE-2026-69641",
              "title": "Exchange EoP — High Severity (Sep 2026)",
              "cvss": 9.1,
              "severity": "critical",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Permits attackers to obtain elevated privileges within Exchange. CVSS 9.1. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69641"
              ]
            },
            {
              "id": "CVE-2025-59249",
              "title": "Exchange EoP — Weak Authentication (Oct 2025)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Weak authentication mechanism enabling privilege escalation. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59249"
              ]
            },
            {
              "id": "CVE-2026-69355",
              "title": "Exchange RCE — Authenticated (Sep 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Authenticated attacker can execute arbitrary code on the Exchange server. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69355"
              ]
            },
            {
              "id": "CVE-2026-62913",
              "title": "Exchange RCE — Heap Buffer Overflow (Aug 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Heap buffer overflow permitting authenticated remote code execution. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62913"
              ]
            },
            {
              "id": "CVE-2026-55005",
              "title": "Exchange RCE — Heap Buffer Overflow (Jul 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Heap-based buffer overflow enabling authenticated remote code execution. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55005"
              ]
            },
            {
              "id": "CVE-2026-45504",
              "title": "Exchange EoP — SSRF (Jun 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "SSRF vulnerability enabling authenticated privilege escalation. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45504"
              ]
            },
            {
              "id": "CVE-2025-53782",
              "title": "Exchange EoP — Authentication Algorithm (Oct 2025)",
              "cvss": 8.4,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Incorrect implementation of authentication algorithm allowing an unauthorized attacker to elevate privileges locally. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53782"
              ]
            },
            {
              "id": "CVE-2026-69380",
              "title": "Exchange EoP — Missing Authorization (Sep 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Missing authorization flaw enabling low-privilege users to read and send mail as other Exchange users. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69380"
              ]
            },
            {
              "id": "CVE-2026-55007",
              "title": "Exchange RCE (Jul/Sep 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Remote code execution vulnerability. Partially addressed in July 2026 SU and fully patched in September 2026 SU. Does not affect Exchange 2016.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55007"
              ]
            },
            {
              "id": "CVE-2026-42897",
              "title": "Exchange XSS / Information Disclosure — Exploited (Jun 2026)",
              "cvss": 8.1,
              "severity": "critical",
              "type": "Information Disclosure / XSS",
              "auth_required": false,
              "exploited_in_wild": true,
              "description": "XSS flaw permitting unauthenticated remote spoofing and information disclosure. Exploited in the wild before patch release. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42897"
              ]
            },
            {
              "id": "CVE-2026-47631",
              "title": "Exchange Spoofing — Input Sanitization (Jun 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Input sanitization flaw enabling unauthenticated spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-47631"
              ]
            },
            {
              "id": "CVE-2026-45503",
              "title": "Exchange Information Disclosure — Authorization Flaw (Jun 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Authorization flaw exposing sensitive Exchange information. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45503"
              ]
            },
            {
              "id": "CVE-2026-62911",
              "title": "Exchange EoP — Replay Authentication Bypass (Aug 2026)",
              "cvss": 8.0,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Replay-based authentication bypass letting an authenticated attacker escalate privileges. Nearly 22,000 exposed servers identified as vulnerable. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62911"
              ]
            },
            {
              "id": "CVE-2026-55009",
              "title": "Exchange EoP — Unsafe Deserialization (Jul/Aug 2026)",
              "cvss": 7.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Unsafe deserialization enabling local privilege elevation. Disclosed July 2026, fully fixed in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55009"
              ]
            },
            {
              "id": "CVE-2026-55006",
              "title": "Exchange EoP — Access Controls (Jul 2026)",
              "cvss": 7.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Overly coarse access controls enabling privilege escalation. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55006"
              ]
            },
            {
              "id": "CVE-2025-33051",
              "title": "Exchange Information Disclosure (Aug 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Exposure of sensitive Exchange information to an unauthorized actor. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33051"
              ]
            },
            {
              "id": "CVE-2025-59248",
              "title": "Exchange Spoofing (Oct 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Input validation flaw permitting unauthorized spoofing. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59248"
              ]
            },
            {
              "id": "CVE-2025-64666",
              "title": "Exchange EoP — Input Validation (Dec 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Improper input validation allowing an authorized attacker to elevate privileges. Patched in December 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64666"
              ]
            },
            {
              "id": "CVE-2026-69378",
              "title": "Exchange DoS (Sep 2026)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Denial of Service",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Allows an attacker to crash the Exchange service. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69378"
              ]
            },
            {
              "id": "CVE-2026-45583",
              "title": "Exchange RCE — Code Injection (Jun 2026)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Code injection flaw permitting unauthenticated remote code execution. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45583"
              ]
            },
            {
              "id": "CVE-2026-62914",
              "title": "Exchange Spoofing — XSS (Aug 2026)",
              "cvss": 7.3,
              "severity": "high",
              "type": "Spoofing / XSS",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Cross-site scripting enabling content spoofing by authenticated users. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62914"
              ]
            },
            {
              "id": "CVE-2026-62910",
              "title": "Exchange EoP — Resource Injection CRITICAL (Aug 2026)",
              "cvss": 7.2,
              "severity": "critical",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Resource injection enabling privilege escalation. Classified critical despite CVSS 7.2 due to attack surface. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62910"
              ]
            },
            {
              "id": "CVE-2025-25005",
              "title": "Exchange Tampering (Aug 2025)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Tampering",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Input validation flaw allowing an authenticated attacker to tamper with Exchange data. Patched in August 2025 SU (first SE SU1, CU15 SU0).",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25005"
              ]
            },
            {
              "id": "CVE-2026-21527",
              "title": "Exchange Spoofing (Feb 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "UI misrepresentation enabling user spoofing by authenticated attackers. Patched in February 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-21527"
              ]
            },
            {
              "id": "CVE-2026-69361",
              "title": "Exchange Spoofing — SSRF (Sep 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Server-side request forgery issue enabling spoofing over the network. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69361"
              ]
            },
            {
              "id": "CVE-2026-69375",
              "title": "Exchange Tampering (Sep 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Tampering",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Enables unauthorized data manipulation in Exchange. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69375"
              ]
            },
            {
              "id": "CVE-2026-65813",
              "title": "Exchange EoP — SSRF (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Server-side request forgery flaw letting an authenticated attacker gain higher privileges remotely. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-65813"
              ]
            },
            {
              "id": "CVE-2026-62915",
              "title": "Exchange Security Feature Bypass (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Security Feature Bypass",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Authorization bypass allowing logged-in users to sidestep Exchange security controls. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62915"
              ]
            },
            {
              "id": "CVE-2026-62912",
              "title": "Exchange DoS — Unsafe Deserialization (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Denial of Service",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Unsafe deserialization allowing service crashes. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62912"
              ]
            },
            {
              "id": "CVE-2026-45501",
              "title": "Exchange Spoofing — SSRF (Jun 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "SSRF vulnerability allowing content spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45501"
              ]
            },
            {
              "id": "CVE-2026-45500",
              "title": "Exchange Spoofing — Output Encoding (Jun 2026)",
              "cvss": 6.1,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Output encoding flaw enabling unauthenticated spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45500"
              ]
            },
            {
              "id": "CVE-2026-69382",
              "title": "Exchange Information Disclosure (Sep 2026)",
              "cvss": 5.9,
              "severity": "medium",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Permits disclosure of restricted Exchange information. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69382"
              ]
            },
            {
              "id": "CVE-2025-25006",
              "title": "Exchange Spoofing (Aug 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Special element handling flaw enabling spoofing of Exchange content. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25006"
              ]
            },
            {
              "id": "CVE-2025-25007",
              "title": "Exchange Spoofing (Aug 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Input validation flaw permitting unauthorized spoofing of Exchange email content. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25007"
              ]
            },
            {
              "id": "CVE-2025-64667",
              "title": "Exchange Spoofing — UI Misrepresentation (Dec 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "UI misrepresentation enabling spoofing of Exchange content. Patched in December 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64667"
              ]
            },
            {
              "id": "CVE-2026-45502",
              "title": "Exchange Information Disclosure — SSRF (Jun 2026)",
              "cvss": 5.0,
              "severity": "medium",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Lower-severity SSRF enabling information leakage from Exchange. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45502"
              ]
            }
          ]
        }
      },
      {
        "source": "owa_fingerprint",
        "url": "https://wmail.azercell.com/ecp/",
        "path": "/ecp/",
        "http_status": 200,
        "disclosures": {
          "body:owa_build_label": "15.2.2562"
        },
        "severity": "low",
        "version_info": {}
      },
      {
        "source": "auth_endpoint",
        "url": "https://wmail.azercell.com/mapi/nspi/",
        "path": "/mapi/nspi/",
        "http_status": 401,
        "auth_required": true,
        "auth_type": "Negotiate",
        "www_authenticate": "Negotiate",
        "disclosures": {
          "X-OWA-Version": "15.2.2562.17",
          "X-FEServer": "MBX19-N01",
          "WWW-Authenticate": "Negotiate",
          "Set-Cookie": "TS0160ab2a=01db3e592ec9a7c9350841f06795185303e2a6ec277ae4c80a2b885e1c0570d2a054b06b14703a278d4048a96b601fc7926245ff56; Path=/; Domain=.wmail.azercell.com",
          "ntlm:target_name": "AZERCELL",
          "ntlm:nb_domain_name": "AZERCELL",
          "ntlm:nb_computer_name": "MBX19-N01",
          "ntlm:dns_domain_name": "azercell.com",
          "ntlm:dns_computer_name": "MBX19-N01.azercell.com",
          "ntlm:dns_tree_name": "azercell.com"
        },
        "severity": "high",
        "version_info": {
          "label": "Exchange SE RTM",
          "build": "15.2.2562.17",
          "release_date": "2025-07-08",
          "kb": "KB5047155",
          "is_latest": false,
          "versions_behind": 10,
          "days_old": 457,
          "cve_count": 38,
          "cves": [
            {
              "id": "CVE-2026-55008",
              "title": "Exchange Spoofing — XSS CRITICAL (Jul 2026)",
              "cvss": 9.6,
              "severity": "critical",
              "type": "Spoofing / XSS",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "XSS allowing unauthenticated spoofing with critical CVSS score of 9.6. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55008"
              ]
            },
            {
              "id": "CVE-2026-69356",
              "title": "Exchange Spoofing — Sender Impersonation (Sep 2026)",
              "cvss": 9.3,
              "severity": "critical",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Allows an attacker to impersonate a different sender in Exchange emails. CVSS 9.3. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69356"
              ]
            },
            {
              "id": "CVE-2026-69641",
              "title": "Exchange EoP — High Severity (Sep 2026)",
              "cvss": 9.1,
              "severity": "critical",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Permits attackers to obtain elevated privileges within Exchange. CVSS 9.1. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69641"
              ]
            },
            {
              "id": "CVE-2025-59249",
              "title": "Exchange EoP — Weak Authentication (Oct 2025)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Weak authentication mechanism enabling privilege escalation. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59249"
              ]
            },
            {
              "id": "CVE-2026-69355",
              "title": "Exchange RCE — Authenticated (Sep 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Authenticated attacker can execute arbitrary code on the Exchange server. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69355"
              ]
            },
            {
              "id": "CVE-2026-62913",
              "title": "Exchange RCE — Heap Buffer Overflow (Aug 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Heap buffer overflow permitting authenticated remote code execution. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62913"
              ]
            },
            {
              "id": "CVE-2026-55005",
              "title": "Exchange RCE — Heap Buffer Overflow (Jul 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Heap-based buffer overflow enabling authenticated remote code execution. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55005"
              ]
            },
            {
              "id": "CVE-2026-45504",
              "title": "Exchange EoP — SSRF (Jun 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "SSRF vulnerability enabling authenticated privilege escalation. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45504"
              ]
            },
            {
              "id": "CVE-2025-53782",
              "title": "Exchange EoP — Authentication Algorithm (Oct 2025)",
              "cvss": 8.4,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Incorrect implementation of authentication algorithm allowing an unauthorized attacker to elevate privileges locally. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53782"
              ]
            },
            {
              "id": "CVE-2026-69380",
              "title": "Exchange EoP — Missing Authorization (Sep 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Missing authorization flaw enabling low-privilege users to read and send mail as other Exchange users. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69380"
              ]
            },
            {
              "id": "CVE-2026-55007",
              "title": "Exchange RCE (Jul/Sep 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Remote code execution vulnerability. Partially addressed in July 2026 SU and fully patched in September 2026 SU. Does not affect Exchange 2016.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55007"
              ]
            },
            {
              "id": "CVE-2026-42897",
              "title": "Exchange XSS / Information Disclosure — Exploited (Jun 2026)",
              "cvss": 8.1,
              "severity": "critical",
              "type": "Information Disclosure / XSS",
              "auth_required": false,
              "exploited_in_wild": true,
              "description": "XSS flaw permitting unauthenticated remote spoofing and information disclosure. Exploited in the wild before patch release. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42897"
              ]
            },
            {
              "id": "CVE-2026-47631",
              "title": "Exchange Spoofing — Input Sanitization (Jun 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Input sanitization flaw enabling unauthenticated spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-47631"
              ]
            },
            {
              "id": "CVE-2026-45503",
              "title": "Exchange Information Disclosure — Authorization Flaw (Jun 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Authorization flaw exposing sensitive Exchange information. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45503"
              ]
            },
            {
              "id": "CVE-2026-62911",
              "title": "Exchange EoP — Replay Authentication Bypass (Aug 2026)",
              "cvss": 8.0,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Replay-based authentication bypass letting an authenticated attacker escalate privileges. Nearly 22,000 exposed servers identified as vulnerable. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62911"
              ]
            },
            {
              "id": "CVE-2026-55009",
              "title": "Exchange EoP — Unsafe Deserialization (Jul/Aug 2026)",
              "cvss": 7.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Unsafe deserialization enabling local privilege elevation. Disclosed July 2026, fully fixed in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55009"
              ]
            },
            {
              "id": "CVE-2026-55006",
              "title": "Exchange EoP — Access Controls (Jul 2026)",
              "cvss": 7.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Overly coarse access controls enabling privilege escalation. Patched in July 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55006"
              ]
            },
            {
              "id": "CVE-2025-33051",
              "title": "Exchange Information Disclosure (Aug 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Exposure of sensitive Exchange information to an unauthorized actor. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33051"
              ]
            },
            {
              "id": "CVE-2025-59248",
              "title": "Exchange Spoofing (Oct 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Input validation flaw permitting unauthorized spoofing. Patched in October 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59248"
              ]
            },
            {
              "id": "CVE-2025-64666",
              "title": "Exchange EoP — Input Validation (Dec 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Improper input validation allowing an authorized attacker to elevate privileges. Patched in December 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64666"
              ]
            },
            {
              "id": "CVE-2026-69378",
              "title": "Exchange DoS (Sep 2026)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Denial of Service",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Allows an attacker to crash the Exchange service. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69378"
              ]
            },
            {
              "id": "CVE-2026-45583",
              "title": "Exchange RCE — Code Injection (Jun 2026)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Code injection flaw permitting unauthenticated remote code execution. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45583"
              ]
            },
            {
              "id": "CVE-2026-62914",
              "title": "Exchange Spoofing — XSS (Aug 2026)",
              "cvss": 7.3,
              "severity": "high",
              "type": "Spoofing / XSS",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Cross-site scripting enabling content spoofing by authenticated users. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62914"
              ]
            },
            {
              "id": "CVE-2026-62910",
              "title": "Exchange EoP — Resource Injection CRITICAL (Aug 2026)",
              "cvss": 7.2,
              "severity": "critical",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Resource injection enabling privilege escalation. Classified critical despite CVSS 7.2 due to attack surface. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62910"
              ]
            },
            {
              "id": "CVE-2025-25005",
              "title": "Exchange Tampering (Aug 2025)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Tampering",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Input validation flaw allowing an authenticated attacker to tamper with Exchange data. Patched in August 2025 SU (first SE SU1, CU15 SU0).",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25005"
              ]
            },
            {
              "id": "CVE-2026-21527",
              "title": "Exchange Spoofing (Feb 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "UI misrepresentation enabling user spoofing by authenticated attackers. Patched in February 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-21527"
              ]
            },
            {
              "id": "CVE-2026-69361",
              "title": "Exchange Spoofing — SSRF (Sep 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Server-side request forgery issue enabling spoofing over the network. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69361"
              ]
            },
            {
              "id": "CVE-2026-69375",
              "title": "Exchange Tampering (Sep 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Tampering",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Enables unauthorized data manipulation in Exchange. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69375"
              ]
            },
            {
              "id": "CVE-2026-65813",
              "title": "Exchange EoP — SSRF (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Server-side request forgery flaw letting an authenticated attacker gain higher privileges remotely. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-65813"
              ]
            },
            {
              "id": "CVE-2026-62915",
              "title": "Exchange Security Feature Bypass (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Security Feature Bypass",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Authorization bypass allowing logged-in users to sidestep Exchange security controls. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62915"
              ]
            },
            {
              "id": "CVE-2026-62912",
              "title": "Exchange DoS — Unsafe Deserialization (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Denial of Service",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Unsafe deserialization allowing service crashes. Patched in August 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62912"
              ]
            },
            {
              "id": "CVE-2026-45501",
              "title": "Exchange Spoofing — SSRF (Jun 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "SSRF vulnerability allowing content spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45501"
              ]
            },
            {
              "id": "CVE-2026-45500",
              "title": "Exchange Spoofing — Output Encoding (Jun 2026)",
              "cvss": 6.1,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Output encoding flaw enabling unauthenticated spoofing. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45500"
              ]
            },
            {
              "id": "CVE-2026-69382",
              "title": "Exchange Information Disclosure (Sep 2026)",
              "cvss": 5.9,
              "severity": "medium",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Permits disclosure of restricted Exchange information. Patched in September 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69382"
              ]
            },
            {
              "id": "CVE-2025-25006",
              "title": "Exchange Spoofing (Aug 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Special element handling flaw enabling spoofing of Exchange content. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25006"
              ]
            },
            {
              "id": "CVE-2025-25007",
              "title": "Exchange Spoofing (Aug 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false,
              "description": "Input validation flaw permitting unauthorized spoofing of Exchange email content. Patched in August 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-25007"
              ]
            },
            {
              "id": "CVE-2025-64667",
              "title": "Exchange Spoofing — UI Misrepresentation (Dec 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "UI misrepresentation enabling spoofing of Exchange content. Patched in December 2025 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64667"
              ]
            },
            {
              "id": "CVE-2026-45502",
              "title": "Exchange Information Disclosure — SSRF (Jun 2026)",
              "cvss": 5.0,
              "severity": "medium",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false,
              "description": "Lower-severity SSRF enabling information leakage from Exchange. Patched in June 2026 SU.",
              "references": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45502"
              ]
            }
          ]
        }
      }
    ],
    "summary": {
      "builds": {
        "15.2.2562.17": {
          "label": "Exchange SE RTM",
          "build": "15.2.2562.17",
          "release_date": "2025-07-08",
          "kb": "KB5047155",
          "days_old": 457,
          "versions_behind": 10,
          "is_latest": false,
          "cves": [
            {
              "id": "CVE-2026-55008",
              "title": "Exchange Spoofing — XSS CRITICAL (Jul 2026)",
              "cvss": 9.6,
              "severity": "critical",
              "type": "Spoofing / XSS",
              "auth_required": false,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2026-69356",
              "title": "Exchange Spoofing — Sender Impersonation (Sep 2026)",
              "cvss": 9.3,
              "severity": "critical",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2026-69641",
              "title": "Exchange EoP — High Severity (Sep 2026)",
              "cvss": 9.1,
              "severity": "critical",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2025-59249",
              "title": "Exchange EoP — Weak Authentication (Oct 2025)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2026-69355",
              "title": "Exchange RCE — Authenticated (Sep 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2026-62913",
              "title": "Exchange RCE — Heap Buffer Overflow (Aug 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2026-55005",
              "title": "Exchange RCE — Heap Buffer Overflow (Jul 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2026-45504",
              "title": "Exchange EoP — SSRF (Jun 2026)",
              "cvss": 8.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2025-53782",
              "title": "Exchange EoP — Authentication Algorithm (Oct 2025)",
              "cvss": 8.4,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": false,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2026-69380",
              "title": "Exchange EoP — Missing Authorization (Sep 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2026-55007",
              "title": "Exchange RCE (Jul/Sep 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": true,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2026-42897",
              "title": "Exchange XSS / Information Disclosure — Exploited (Jun 2026)",
              "cvss": 8.1,
              "severity": "critical",
              "type": "Information Disclosure / XSS",
              "auth_required": false,
              "exploited_in_wild": true
            },
            {
              "id": "CVE-2026-47631",
              "title": "Exchange Spoofing — Input Sanitization (Jun 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2026-45503",
              "title": "Exchange Information Disclosure — Authorization Flaw (Jun 2026)",
              "cvss": 8.1,
              "severity": "high",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2026-62911",
              "title": "Exchange EoP — Replay Authentication Bypass (Aug 2026)",
              "cvss": 8.0,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2026-55009",
              "title": "Exchange EoP — Unsafe Deserialization (Jul/Aug 2026)",
              "cvss": 7.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2026-55006",
              "title": "Exchange EoP — Access Controls (Jul 2026)",
              "cvss": 7.8,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2025-33051",
              "title": "Exchange Information Disclosure (Aug 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2025-59248",
              "title": "Exchange Spoofing (Oct 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2025-64666",
              "title": "Exchange EoP — Input Validation (Dec 2025)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2026-69378",
              "title": "Exchange DoS (Sep 2026)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Denial of Service",
              "auth_required": false,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2026-45583",
              "title": "Exchange RCE — Code Injection (Jun 2026)",
              "cvss": 7.5,
              "severity": "high",
              "type": "Remote Code Execution",
              "auth_required": false,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2026-62914",
              "title": "Exchange Spoofing — XSS (Aug 2026)",
              "cvss": 7.3,
              "severity": "high",
              "type": "Spoofing / XSS",
              "auth_required": true,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2026-62910",
              "title": "Exchange EoP — Resource Injection CRITICAL (Aug 2026)",
              "cvss": 7.2,
              "severity": "critical",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2025-25005",
              "title": "Exchange Tampering (Aug 2025)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Tampering",
              "auth_required": true,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2026-21527",
              "title": "Exchange Spoofing (Feb 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2026-69361",
              "title": "Exchange Spoofing — SSRF (Sep 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2026-69375",
              "title": "Exchange Tampering (Sep 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Tampering",
              "auth_required": false,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2026-65813",
              "title": "Exchange EoP — SSRF (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Elevation of Privilege",
              "auth_required": true,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2026-62915",
              "title": "Exchange Security Feature Bypass (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Security Feature Bypass",
              "auth_required": true,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2026-62912",
              "title": "Exchange DoS — Unsafe Deserialization (Aug 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Denial of Service",
              "auth_required": true,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2026-45501",
              "title": "Exchange Spoofing — SSRF (Jun 2026)",
              "cvss": 6.5,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2026-45500",
              "title": "Exchange Spoofing — Output Encoding (Jun 2026)",
              "cvss": 6.1,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2026-69382",
              "title": "Exchange Information Disclosure (Sep 2026)",
              "cvss": 5.9,
              "severity": "medium",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2025-25006",
              "title": "Exchange Spoofing (Aug 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2025-25007",
              "title": "Exchange Spoofing (Aug 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": true,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2025-64667",
              "title": "Exchange Spoofing — UI Misrepresentation (Dec 2025)",
              "cvss": 5.3,
              "severity": "medium",
              "type": "Spoofing",
              "auth_required": false,
              "exploited_in_wild": false
            },
            {
              "id": "CVE-2026-45502",
              "title": "Exchange Information Disclosure — SSRF (Jun 2026)",
              "cvss": 5.0,
              "severity": "medium",
              "type": "Information Disclosure",
              "auth_required": false,
              "exploited_in_wild": false
            }
          ]
        }
      },
      "ntlm_disclosures": {
        "target_name": [
          "AZERCELL"
        ],
        "nb_domain_name": [
          "AZERCELL"
        ],
        "nb_computer_name": [
          "MBX19-N01"
        ],
        "dns_domain_name": [
          "azercell.com"
        ],
        "dns_computer_name": [
          "MBX19-N01.azercell.com"
        ],
        "dns_tree_name": [
          "azercell.com"
        ]
      },
      "endpoints": [
        {
          "source": "auth_endpoint",
          "path": "/rpc/rpcproxy.dll",
          "http_status": "401",
          "auth": "Basic",
          "severity": "high",
          "unique_disclosures": {
            "X-OWA-Version": "15.2.2562.17",
            "WWW-Authenticate": "Basic realm=\"wmail.azercell.com\"",
            "Set-Cookie": "TS0160ab2a=01db3e592ea1baa346452fb3cb26c53bdc7726b70a7b35812d258a4cb9e27f5e7d18e65ccec0ac0414b0c2c557bf7121a01b2f0343; Path=/; Domain=.wmail.azercell.com"
          }
        },
        {
          "source": "mapi_connect",
          "path": "/mapi/emsmdb/",
          "http_status": "200",
          "auth": "open",
          "severity": "low",
          "unique_disclosures": {}
        },
        {
          "source": "owa_fingerprint",
          "path": "/sites/",
          "http_status": "404",
          "auth": "",
          "severity": "low",
          "unique_disclosures": {
            "Set-Cookie": "TS0160ab2a=01db3e592e9a30146293f4751f7fbc684504db243fa74e33b4328eda6bba34a4a8ff66cd60b6e3fd07bfa0ffdeac3edaa9337a9512; Path=/; Domain=.wmail.azercell.com"
          }
        },
        {
          "source": "autodiscover_xml",
          "path": "/autodiscover/autodiscover.xml",
          "http_status": "302",
          "auth": "",
          "severity": "low",
          "unique_disclosures": {
            "Set-Cookie": "evo1xcukdl=3knlg586qpe54ts2fslufmns7l; path=/; secure; HttpOnly"
          }
        },
        {
          "source": "auth_endpoint",
          "path": "/PowerShell/",
          "http_status": "401",
          "auth": "Kerberos",
          "severity": "high",
          "unique_disclosures": {
            "X-OWA-Version": "15.2.2562.17",
            "X-FEServer": "MBX19-N01",
            "WWW-Authenticate": "Kerberos",
            "Set-Cookie": "TS0160ab2a=01db3e592e257589538dbebacb99a7f358fe46c12313213e4ce1ccb3d7d21148ef8ba739a51a0deb9c1056f8ac1552b65c71645391; Path=/; Domain=.wmail.azercell.com"
          }
        },
        {
          "source": "auth_endpoint",
          "path": "/Rpc/",
          "http_status": "401",
          "auth": "Basic",
          "severity": "high",
          "unique_disclosures": {
            "X-OWA-Version": "15.2.2562.17",
            "WWW-Authenticate": "Basic realm=\"wmail.azercell.com\"",
            "Set-Cookie": "TS0160ab2a=01db3e592e9ee77d132a098c89f4d0d266ad5bf411361b76bff3a7a515c460004ab2208b7eacd8c1a9ef716b6adc3f5c1149f182d1; Path=/; Domain=.wmail.azercell.com"
          }
        },
        {
          "source": "mapi_connect",
          "path": "/mapi/emsmdb/",
          "http_status": "401",
          "auth": "",
          "severity": "high",
          "unique_disclosures": {
            "X-OWA-Version": "15.2.2562.17",
            "X-FEServer": "MBX19-N01",
            "WWW-Authenticate": "Negotiate",
            "Set-Cookie": "TS0160ab2a=01db3e592ec2975c8a359b72967f0c748d7659147f472d96a3af576cf8c18c64f6c51c750496e22d4db6188c1e87b84d6cff4f75d7; Path=/; Domain=.wmail.azercell.com"
          }
        },
        {
          "source": "autodiscover_xml",
          "path": "/autodiscover/autodiscover.xml",
          "http_status": "404",
          "auth": "",
          "severity": "low",
          "unique_disclosures": {
            "Set-Cookie": "TS0160ab2a=01db3e592e9ddfad432e0c90892ca053f248443073aa71f1b82a75c5ff39f8ca090fc779d9d312ca7b0171e78ac026445ed7db6ad5; Path=/; Domain=.wmail.azercell.com"
          }
        },
        {
          "source": "ews_soap",
          "path": "/EWS/Exchange.asmx",
          "http_status": "401",
          "auth": "",
          "severity": "high",
          "unique_disclosures": {
            "X-OWA-Version": "15.2.2562.17",
            "X-FEServer": "MBX19-N01",
            "WWW-Authenticate": "Basic realm=\"wmail.azercell.com\"",
            "Set-Cookie": "TS0160ab2a=01db3e592e7edfa44836cf0195c7fe92c492ed717277f989f29c8bc25584f2a23409c29ea5895d7654847696750ee709db0de443c4; Path=/; Domain=.wmail.azercell.com"
          }
        },
        {
          "source": "owa_fingerprint",
          "path": "/_api/web",
          "http_status": "404",
          "auth": "",
          "severity": "low",
          "unique_disclosures": {
            "Set-Cookie": "TS0160ab2a=01db3e592ed959162eb52b267b26441a44d2c795337b945d3f18d3e45795e33dcb70baf66032823b21e8c5d5ebacf4e33c456c14c7; Path=/; Domain=.wmail.azercell.com"
          }
        },
        {
          "source": "auth_endpoint",
          "path": "/EWS/Exchange.asmx",
          "http_status": "401",
          "auth": "Basic",
          "severity": "high",
          "unique_disclosures": {
            "X-OWA-Version": "15.2.2562.17",
            "X-FEServer": "MBX19-N01",
            "X-WSSecurity-For": "None",
            "WWW-Authenticate": "Basic realm=\"wmail.azercell.com\"",
            "Set-Cookie": "TS0160ab2a=01db3e592e197063ef8619aff0579842f1d4c3dee017d0340cd94f21b83de4c3195558f2896cb2d7460ef2de9fb505c7e9f89c7db7; Path=/; Domain=.wmail.azercell.com"
          }
        },
        {
          "source": "mapi_connect",
          "path": "/mapi/",
          "http_status": "401",
          "auth": "",
          "severity": "high",
          "unique_disclosures": {
            "X-OWA-Version": "15.2.2562.17",
            "X-FEServer": "MBX19-N01",
            "WWW-Authenticate": "Negotiate",
            "Set-Cookie": "TS0160ab2a=01db3e592eb03e16b43f4c8a638e83b47a98a5fe54335d16925ea75b2ee1a910404b53056286ed7a2392acac59af2dbf5ee7ba1787; Path=/; Domain=.wmail.azercell.com"
          }
        },
        {
          "source": "autodiscover_v2",
          "path": "/.well-known/autodiscover.json",
          "http_status": "404",
          "auth": "",
          "severity": "info",
          "unique_disclosures": {
            "Set-Cookie": "TS0160ab2a=01db3e592e728f9cb057bc71bf9736d69d2d65d3660ded71bb888b27495f99ac7310ed0cd0d596d77418f054545a85a816fec2d6eb; Path=/; Domain=.wmail.azercell.com"
          }
        },
        {
          "source": "owa_fingerprint",
          "path": "/owa/auth/errorFE.aspx",
          "http_status": "500",
          "auth": "",
          "severity": "high",
          "unique_disclosures": {
            "X-OWA-Version": "15.2.2562.17",
            "X-FEServer": "MBX19-N01",
            "Set-Cookie": "TS0160ab2a=01db3e592e3ad992ea64d0595dcc3bb5ff9fb5e67448a0e1d60306272a02e1efb2bb47eb312515dd5502f70b9725db27f3f49f21c4; Path=/; Domain=.wmail.azercell.com",
            "body:error_server": "MBX19-N01",
            "body:internal_hostname": "MBX19-N01",
            "body:owa_build_label": "15.2.2562"
          }
        },
        {
          "source": "owa_fingerprint",
          "path": "/aspnet_client/",
          "http_status": "500",
          "auth": "",
          "severity": "low",
          "unique_disclosures": {
            "Set-Cookie": "TS0160ab2a=01db3e592e74ba3e395eed4bce0492c13b177acb15b2b125e7f53f04fd3c497217d39f7157f8138e19b29be6c651ddee0e0a71f188; Path=/; Domain=.wmail.azercell.com"
          }
        },
        {
          "source": "owa_fingerprint",
          "path": "/owa/auth/expiredpassword.aspx",
          "http_status": "200",
          "auth": "open",
          "severity": "low",
          "unique_disclosures": {
            "Set-Cookie": "TS0160ab2a=01db3e592eb8607850963e2e93faacc31f161aea6fa48146ecbce2291cd9fb1f86f382807c2572b6123c0eb374519559b175ef0364; Path=/; Domain=.wmail.azercell.com"
          }
        },
        {
          "source": "owa_fingerprint",
          "path": "/cscp/",
          "http_status": "404",
          "auth": "",
          "severity": "low",
          "unique_disclosures": {
            "Set-Cookie": "TS0160ab2a=01db3e592e0272753b4e97f2253ddb38034e8800d26eb40733b23947e21b0731990af3a539b8358b9acdfc8ebfca57b08de15310c8; Path=/; Domain=.wmail.azercell.com"
          }
        },
        {
          "source": "autodiscover_v2",
          "path": "/autodiscover/autodiscover.json",
          "http_status": "404",
          "auth": "",
          "severity": "info",
          "unique_disclosures": {
            "Set-Cookie": "TS0160ab2a=01db3e592e5eaabf6882342741db9067e2353db35db0b54b7458292703fdfcdc3f94e37e039daa6852e8139605eaabed00db42af88; Path=/; Domain=.wmail.azercell.com"
          }
        },
        {
          "source": "auth_endpoint",
          "path": "/EWS/Services.wsdl",
          "http_status": "401",
          "auth": "Basic",
          "severity": "high",
          "unique_disclosures": {
            "X-OWA-Version": "15.2.2562.17",
            "X-FEServer": "MBX19-N01",
            "X-WSSecurity-For": "None",
            "WWW-Authenticate": "Basic realm=\"wmail.azercell.com\"",
            "Set-Cookie": "TS0160ab2a=01db3e592e2731acf8e2eaa95da023f05c18c7fe678761388b403b2cb5fce552f2e3d72638cc0b07c5a305159f27a48c13130f9e0f; Path=/; Domain=.wmail.azercell.com"
          }
        },
        {
          "source": "owa_fingerprint",
          "path": "/owa/auth/logon.aspx",
          "http_status": "200",
          "auth": "open",
          "severity": "low",
          "unique_disclosures": {
            "Set-Cookie": "TS0160ab2a=01db3e592e51fb8f321a547f997aa5ed24a2f0433c276275346cfb610d1e44e704d161adb31a640205d40b403b792e5175b9390d4c; Path=/; Domain=.wmail.azercell.com",
            "body:owa_build_label": "15.2.2562"
          }
        },
        {
          "source": "mapi_connect",
          "path": "/mapi/nspi/",
          "http_status": "401",
          "auth": "",
          "severity": "high",
          "unique_disclosures": {
            "X-OWA-Version": "15.2.2562.17",
            "X-FEServer": "MBX19-N01",
            "WWW-Authenticate": "Negotiate",
            "Set-Cookie": "TS0160ab2a=01db3e592eb7102dec7b28aaa22ff508c0de00ef5ae36dc833c920d801633f9c4144abf7d03226aceaa7a535302ae5e5696346d6de; Path=/; Domain=.wmail.azercell.com"
          }
        },
        {
          "source": "auth_endpoint",
          "path": "/mapi/emsmdb/",
          "http_status": "401",
          "auth": "Negotiate",
          "severity": "high",
          "unique_disclosures": {
            "X-OWA-Version": "15.2.2562.17",
            "X-FEServer": "MBX19-N01",
            "WWW-Authenticate": "Negotiate",
            "Set-Cookie": "TS0160ab2a=01db3e592e624f3e263c61af01a38ccac488830dd11889f9935d17d785407ec7e506e9fbbb92e3aefec1bf2a013e276db7541ab401; Path=/; Domain=.wmail.azercell.com"
          }
        },
        {
          "source": "auth_endpoint",
          "path": "/mapi/",
          "http_status": "401",
          "auth": "Negotiate",
          "severity": "high",
          "unique_disclosures": {
            "X-OWA-Version": "15.2.2562.17",
            "X-FEServer": "MBX19-N01",
            "WWW-Authenticate": "Negotiate",
            "Set-Cookie": "TS0160ab2a=01db3e592e9d9b99e4cfb4a24de53fa58fd64ca890678669cf675aaa6c1e9f9f60dfbe1647c10f719ae1378a480268f57c91dee0a0; Path=/; Domain=.wmail.azercell.com"
          }
        },
        {
          "source": "auth_endpoint",
          "path": "/Microsoft-Server-ActiveSync",
          "http_status": "401",
          "auth": "Basic",
          "severity": "high",
          "unique_disclosures": {
            "X-OWA-Version": "15.2.2562.17",
            "X-FEServer": "MBX19-N01",
            "WWW-Authenticate": "Basic realm=\"wmail.azercell.com\"",
            "Set-Cookie": "TS0160ab2a=01db3e592e85d0057933d403c159fc9104e97a262f7ebbc0eb7c545c0765b0705eadee6f60037c4bc33708776036b30430acc89bde; Path=/; Domain=.wmail.azercell.com"
          }
        },
        {
          "source": "owa_fingerprint",
          "path": "/owa/",
          "http_status": "200",
          "auth": "open",
          "severity": "low",
          "unique_disclosures": {
            "body:owa_build_label": "15.2.2562"
          }
        },
        {
          "source": "ediscovery_manifest",
          "path": "/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application",
          "http_status": "200",
          "auth": "open",
          "severity": "high",
          "unique_disclosures": {
            "ediscovery:exchange_build": "15.2.2562.17",
            "ediscovery:assembly_name": "microsoft.exchange.ediscovery.exporttool.application",
            "X-FEServer": "MBX19-N01",
            "X-BEServer": "MBX19-N02",
            "X-DiagInfo": "MBX19-N02",
            "X-CalculatedBETarget": "mbx19-n02.azercell.com",
            "Set-Cookie": "TS0160ab2a=01db3e592e857b1b254d304f5d0630bea28891fed54c8e6ad15fa12aeaa04aced0d3c79acd5daf9d8945ae5c31ec0edf615b154518; Path=/; Domain=.wmail.azercell.com"
          }
        },
        {
          "source": "auth_endpoint",
          "path": "/OAB/",
          "http_status": "401",
          "auth": "Negotiate",
          "severity": "high",
          "unique_disclosures": {
            "X-OWA-Version": "15.2.2562.17",
            "X-FEServer": "MBX19-N01",
            "WWW-Authenticate": "Negotiate",
            "Set-Cookie": "TS0160ab2a=01db3e592eaa2c74ae2889bc0bf89d5a7466ae401b6b503ad24f1e53548b206a9bd9e8fe76176bcd9763f7912b43dc3cd1f17a69d6; Path=/; Domain=.wmail.azercell.com"
          }
        },
        {
          "source": "owa_fingerprint",
          "path": "/ecp/",
          "http_status": "200",
          "auth": "open",
          "severity": "low",
          "unique_disclosures": {
            "body:owa_build_label": "15.2.2562"
          }
        },
        {
          "source": "auth_endpoint",
          "path": "/mapi/nspi/",
          "http_status": "401",
          "auth": "Negotiate",
          "severity": "high",
          "unique_disclosures": {
            "X-OWA-Version": "15.2.2562.17",
            "X-FEServer": "MBX19-N01",
            "WWW-Authenticate": "Negotiate",
            "Set-Cookie": "TS0160ab2a=01db3e592ec9a7c9350841f06795185303e2a6ec277ae4c80a2b885e1c0570d2a054b06b14703a278d4048a96b601fc7926245ff56; Path=/; Domain=.wmail.azercell.com"
          }
        }
      ]
    }
  }
}
```


---

