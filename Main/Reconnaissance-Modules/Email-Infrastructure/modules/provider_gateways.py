import re
from typing import Optional

from .base import BaseEmailModule


PROVIDER_SIGNATURES = {
    "Google Workspace": ["google.com", "googlemail.com", "aspmx.l.google.com"],
    "Microsoft 365": ["mail.protection.outlook.com", "outlook.com"],
    "Zoho Mail": ["zoho.com", "mx.zoho.com"],
    "ProtonMail": ["protonmail.ch", "mail.protonmail.ch"],
    "Fastmail": ["fastmail.com", "fastmail.fm"],
    "Yahoo Mail": ["yahoodns.net", "yahoo.com"],
    "iCloud Mail": ["icloud.com", "me.com"],
    "Rackspace": ["emailsrvr.com", "rackspace.com"],
    "Mailgun": ["mailgun.org"],
    "SendGrid": ["sendgrid.net"],
    "Amazon SES": ["amazonses.com", "amazonaws.com"],
    "SparkPost": ["sparkpostmail.com", "sp.prd.sparkpost.com"],
    "Postmark": ["spamgourmet.com"],
    "Namecheap Mail": ["privateemail.com"],
    "GoDaddy": ["secureserver.net", "godaddy.com"],
    "Bluehost": ["bluehost.com"],
    "cPanel": ["cpanel.com", "cpanelemail.com"],
}

SECURITY_GATEWAY_SIGNATURES = {
    "Proofpoint": ["pphosted.com", "proofpoint.com", "ppe-hosted.com"],
    "Mimecast": ["mimecast.com"],
    "Barracuda": ["barracudanetworks.com", "ess.barracudanetworks.com"],
    "Cisco IronPort": ["iphmx.com"],
    "Sophos": ["sophos.com", "reflexion.net"],
    "Fortinet": ["fortimail.com"],
    "SpamTitan": ["spamtitan.com"],
    "MX Guarddog": ["mxgd.net"],
    "Symantec": ["messagelabs.com"],
    "Microsoft ATP": ["mail.protection.outlook.com"],
    "Egress": ["egress.com"],
    "Abnormal Security": ["abnormalsecurity.com"],
}

RELAY_TXT_PATTERNS = {
    "SendGrid": r"sendgrid\.net",
    "Mailgun": r"mailgun\.org",
    "Amazon SES": r"amazonses\.com",
    "Mailchimp": r"mailchimp\.com|mandrill\.com",
    "SparkPost": r"sparkpostmail\.com",
    "Postmark": r"sppostmark\.net",
    "Brevo (Sendinblue)": r"sendinblue\.com|brevo\.com",
    "Zoho Campaigns": r"zohoinsights\.com",
    "HubSpot": r"hubspotemail\.net|hubspot\.com",
    "Salesforce": r"exacttarget\.com|salesforce\.com",
}


class ProviderGatewaysModule(BaseEmailModule):

    async def run(self, domain: str) -> dict:
        mx_records = await self._resolver.mx(domain)
        txt_records = await self._resolver.txt(domain)

        provider = self.identify_email_provider(mx_records)
        relays = self.detect_mail_relays(txt_records)
        gateways = self.fingerprint_security_gateways(mx_records)

        return {
            "email_provider": provider,
            "mail_relays": relays,
            "security_gateways": gateways,
        }

    def identify_email_provider(self, mx_records: list[dict]) -> dict:
        if not mx_records:
            return {"name": "Unknown", "confidence": 0.0, "mx_hosts": []}

        mx_hosts = [rec["host"].lower() for rec in mx_records]

        for provider_name, signatures in PROVIDER_SIGNATURES.items():
            for host in mx_hosts:
                for sig in signatures:
                    if sig in host:
                        self._logger.finding(
                            "PROVIDER",
                            "Identified",
                            provider_name,
                            confidence=0.95,
                        )
                        return {
                            "name": provider_name,
                            "confidence": 0.95,
                            "mx_hosts": mx_hosts,
                            "matched_signature": sig,
                        }

        self._logger.warning("[PROVIDER-GW] Provider not identified from known signatures")
        return {
            "name": "Self-hosted / Unknown",
            "confidence": 0.3,
            "mx_hosts": mx_hosts,
            "matched_signature": None,
        }

    def detect_mail_relays(self, txt_records: list[str]) -> list[dict]:
        found_relays = []
        combined = " ".join(txt_records).lower()

        for relay_name, pattern in RELAY_TXT_PATTERNS.items():
            if re.search(pattern, combined, re.IGNORECASE):
                self._logger.finding(
                    "RELAY",
                    "Third-party relay",
                    relay_name,
                    confidence=0.85,
                )
                found_relays.append({
                    "service": relay_name,
                    "confidence": 0.85,
                    "detected_via": "TXT record",
                })

        return found_relays

    def fingerprint_security_gateways(self, mx_records: list[dict]) -> list[dict]:
        found_gateways = []
        mx_hosts = [rec["host"].lower() for rec in mx_records]

        for gateway_name, signatures in SECURITY_GATEWAY_SIGNATURES.items():
            for host in mx_hosts:
                for sig in signatures:
                    if sig in host:
                        self._logger.finding(
                            "GATEWAY",
                            "Security gateway",
                            gateway_name,
                            confidence=0.9,
                        )
                        found_gateways.append({
                            "vendor": gateway_name,
                            "matched_host": host,
                            "matched_signature": sig,
                            "confidence": 0.9,
                        })
                        break

        return found_gateways