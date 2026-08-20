# Module imports
import azure.functions as func
import json
import dns.resolver
import dns.exception
import requests
import whois
import smtplib
import socket
import ssl
import re
import html
import os
import ipaddress
import uuid
import contextlib
import io
from datetime import datetime, timezone

# Function settings
app = func.FunctionApp()

def float_env(name, default):
    try:
        return float(os.environ.get(name, str(default)))
    except ValueError:
        return default

def configure_default_dns_resolver():
    resolver = dns.resolver.Resolver()
    resolver.timeout = float_env("DNS_QUERY_TIMEOUT", 1.5)
    resolver.lifetime = float_env("DNS_QUERY_LIFETIME", 3.0)
    dns.resolver.default_resolver = resolver

configure_default_dns_resolver()

DEFAULT_DNSBL_ZONES = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "psbl.surriel.com",
    "spam.spamrats.com",
    "rbl.interserver.net",
    "bl.mailspike.net",
]

def get_dnsbl_zones():
    # Comma-separated override for deployments that want a different DNSBL set.
    configured = os.environ.get("DNSBL_ZONES", "").strip()
    if configured:
        zones = [zone.strip().strip(".").lower() for zone in configured.split(",") if zone.strip()]
        return zones or DEFAULT_DNSBL_ZONES
    return DEFAULT_DNSBL_ZONES

def reverse_ipv4(ip):
    return ".".join(reversed(ip.split(".")))

def reverse_ipv6(ip):
    expanded = ipaddress.ip_address(ip).exploded.replace(":", "")
    return ".".join(reversed(expanded))

def make_dnsbl_query(ip, zone):
    parsed = ipaddress.ip_address(ip)
    if parsed.version == 4:
        return f"{reverse_ipv4(ip)}.{zone}"
    return f"{reverse_ipv6(ip)}.{zone}"

def is_dnsbl_access_blocked(answers):
    # Some DNSBL providers return 127.255.255.x when the resolver is blocked or not authorized.
    # Do not count those responses as a real blacklist listing.
    return any(str(answer).startswith("127.255.255.") for answer in answers)

def resolve_mx_host_ips(mx_host):
    try:
        max_ips = max(1, int(os.environ.get("DNSBL_MAX_IPS_PER_MX", "2")))
    except ValueError:
        max_ips = 2
    ips = []
    for record_type in ("A", "AAAA"):
        try:
            records = dns.resolver.resolve(mx_host, record_type, lifetime=3)
            for record in records:
                ip = str(record)
                if ip not in ips:
                    ips.append(ip)
                    if len(ips) >= max_ips:
                        return ips
        except Exception:
            continue
    return ips

def check_ip_against_dnsbls(ip, zones):
    listed_zones = []
    checked_zones = 0
    unavailable_zones = []

    resolver = dns.resolver.Resolver()
    resolver.timeout = 0.6
    resolver.lifetime = 0.8

    for zone in zones:
        query = make_dnsbl_query(ip, zone)
        try:
            answers = resolver.resolve(query, "A")
            if is_dnsbl_access_blocked(answers):
                unavailable_zones.append(zone)
                continue
            checked_zones += 1
            listed_zones.append(zone)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            checked_zones += 1
        except (dns.exception.Timeout, dns.resolver.NoNameservers):
            unavailable_zones.append(zone)
        except Exception:
            unavailable_zones.append(zone)

    return {
        "ip": ip,
        "listed_zones": listed_zones,
        "checked_zones": checked_zones,
        "unavailable_zones": unavailable_zones,
    }

def build_blacklist_summary(checks):
    listed_by_zone = {}
    checked_zones = set()
    unavailable_zones = set()
    checked_ips = []

    for check in checks:
        checked_ips.append(check["ip"])
        for zone in check["listed_zones"]:
            listed_by_zone.setdefault(zone, set()).add(check["ip"])
        for zone in check["unavailable_zones"]:
            unavailable_zones.add(zone)

    # A zone counts as checked when at least one IP received a definite listed/not-listed response.
    zones = get_dnsbl_zones()
    for zone in zones:
        for check in checks:
            if zone not in check["unavailable_zones"]:
                checked_zones.add(zone)
                break

    listed_count = len(listed_by_zone)
    checked_count = len(checked_zones)
    ip_count = len(checked_ips)

    if checked_count == 0:
        return {
            "listed_count": 0,
            "checked_count": 0,
            "listed_by_zone": listed_by_zone,
            "line": "Blacklist check: unavailable",
            "advisories": [],
        }

    line = f"Blacklist matches: {listed_count}/{checked_count} checked"
    if ip_count > 1:
        line += f" across {ip_count} IP addresses"
    if listed_count > 0:
        listed_names = ", ".join(sorted(listed_by_zone.keys()))
        line += f" ({listed_names})"

    advisories = []
    if listed_count > 0:
        details = []
        for zone, ips in sorted(listed_by_zone.items()):
            details.append(f"{zone}: {', '.join(sorted(ips))}")
        advisories.append("MX server is listed on one or more DNS blacklists: " + "; ".join(details))

    return {
        "listed_count": listed_count,
        "checked_count": checked_count,
        "listed_by_zone": listed_by_zone,
        "line": line,
        "advisories": advisories,
    }

def worse_level(*levels):
    priority = {"error": 3, "warning": 2, "success": 1, None: 0}
    worst = None
    for level in levels:
        if priority.get(level, 0) > priority.get(worst, 0):
            worst = level
    return worst

def check_mx_blacklists(mx_hosts, certificate_checks=None):
    certificate_checks = certificate_checks or {}
    zones = get_dnsbl_zones()
    values = []
    advisories = []
    total_listed = 0
    unresolved_hosts = []

    for mx_host in mx_hosts:
        details = []
        ips = resolve_mx_host_ips(mx_host)
        if not ips:
            unresolved_hosts.append(mx_host)
            details.append("Blacklist check: unavailable, MX host IP address could not be resolved")
        else:
            checks = [check_ip_against_dnsbls(ip, zones) for ip in ips]
            summary = build_blacklist_summary(checks)
            total_listed += summary["listed_count"]
            advisories.extend(summary["advisories"])
            details.append(summary["line"])

        certificate_check = certificate_checks.get(mx_host)
        if certificate_check:
            details.append(certificate_check["line"])

        values.append({
            "text": mx_host,
            "details": details,
        })

    if unresolved_hosts:
        host_list = ", ".join(unresolved_hosts)
        advisories.append(f"MX host address record not found for: {host_list}. Add an A or AAAA record for each MX host.")

    return values, advisories, total_listed, unresolved_hosts



def normalize_txt_value(value):
    return str(value).strip().strip('"').lower()

def same_txt_record_set(left, right):
    return sorted(normalize_txt_value(value) for value in left) == sorted(normalize_txt_value(value) for value in right)

def looks_like_wildcard_txt_response(record_name, txt_values):
    # DNS wildcard responses are synthesized as if they exist on the queried name.
    # To avoid accepting wildcard TXT records as DMARC/TLS-RPT/MTA-STS, query a random
    # sibling below the same parent. If it returns the exact same TXT set, the original
    # response is most likely wildcard-generated and not a dedicated scoped record.
    if not txt_values:
        return False

    labels = clean_dns_name(record_name).split('.')
    if len(labels) < 2:
        return False

    parent = '.'.join(labels[1:])
    probe_name = f"_dnstool_probe_{uuid.uuid4().hex[:12]}.{parent}"
    try:
        probe_records = dns.resolver.resolve(probe_name, 'TXT', lifetime=2)
        probe_values = txt_record_values(probe_records)
        return same_txt_record_set(txt_values, probe_values)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return False
    except Exception:
        # If the wildcard probe cannot be completed, do not block the real result.
        return False

def resolve_scoped_txt(record_name, expected_prefix):
    values = txt_record_values(dns.resolver.resolve(record_name, 'TXT'))
    prefix = expected_prefix.lower()
    valid_records = [value for value in values if value.strip().lower().startswith(prefix)]
    unexpected_records = [value for value in values if not value.strip().lower().startswith(prefix)]
    wildcard_shadowed = looks_like_wildcard_txt_response(record_name, values)

    if wildcard_shadowed:
        # Treat wildcard-generated scoped security records as missing. A domain should
        # publish a dedicated TXT record on the exact required name.
        valid_records = []

    return {
        "record_name": record_name,
        "expected_prefix": expected_prefix,
        "all_records": values,
        "valid_records": valid_records,
        "unexpected_records": unexpected_records,
        "wildcard_shadowed": wildcard_shadowed,
    }

def scoped_txt_advisories(record_type, scoped, base_advisory=None):
    record_name = scoped["record_name"]
    expected_prefix = scoped["expected_prefix"]
    advisories = []

    if base_advisory:
        advisories.append(base_advisory)

    if scoped.get("wildcard_shadowed"):
        advisories.append(
            f"TXT records returned for {record_name} appear to come from a wildcard response. "
            f"Publish a dedicated {record_type} TXT record on {record_name} that starts with {expected_prefix}."
        )
    elif scoped.get("all_records") and not scoped.get("valid_records"):
        advisories.append(
            f"TXT record(s) found on {record_name}, but none start with {expected_prefix}."
        )

    if scoped.get("valid_records") and scoped.get("unexpected_records"):
        advisories.append(
            f"Unrelated TXT record(s) were also found on {record_name}. Keep this name dedicated to {record_type} records."
        )

    return advisories

def record_not_found(record_type, domain):
    return f"{record_type} record not found: {domain}"

def is_dns_resolution_failure(error):
    return isinstance(error, (dns.resolver.NoNameservers, dns.exception.Timeout))

def dns_failure_message(domain, error):
    return f"DNS lookup failed for {domain}: {str(error)}"

def get_domain_dns_resolution_failure(domain):
    for record_type in ("SOA", "NS"):
        try:
            dns.resolver.resolve(domain, record_type, lifetime=2)
            return None
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            return None
        except Exception as error:
            if is_dns_resolution_failure(error):
                return dns_failure_message(domain, error)
            return dns_failure_message(domain, error)
    return None

def dns_unavailable_advisory():
    return (
        "The domain DNS is currently returning SERVFAIL or timing out, so records "
        "cannot be validated. Check DNSSEC delegation, authoritative nameservers, "
        "and zone health."
    )

def build_dns_failure_lookup_payload(domain, message):
    advisory = dns_unavailable_advisory()
    return {
        "MX": make_record(False, message, [advisory], level="error"),
        "SPF": make_record(False, message, [advisory], level="error"),
        "DKIM": make_record(False, message, [advisory], level="error"),
        "DMARC": make_record(False, message, [advisory], level="error"),
        "TLS-RPT": make_record(False, message, [advisory], level="warning"),
        "DNSSEC": make_record(False, message, [advisory], level="error"),
        "DANE": make_record(False, "No MX host available for DANE check", [advisory], level="error"),
        "MTA-STS": make_record(False, message, [advisory], level="warning"),
        "NS": [],
        "WHOIS": empty_whois_payload(domain, "dns_error", message),
    }

def txt_record_values(records):
    return ["".join([b.decode("utf-8") for b in r.strings]) for r in records]

DOMAIN_DETAIL_RECORD_TYPES = ["A", "AAAA", "CNAME", "TXT", "NS", "MX", "SOA", "CAA", "DS", "DNSKEY"]

DOMAIN_DETAIL_DISCOVERY_NAMES = {
    "TXT": [
        "_dmarc",
        "_mta-sts",
        "_smtp._tls",
        "_msradc",
        "_bimi",
        "default._bimi",
        "_domainconnect",
        "_github-pages-challenge",
        "_acme-challenge",
    ],
    "CNAME": [
        "autodiscover",
        "EnterpriseEnrollment",
        "EnterpriseRegistration",
        "selector1._domainkey",
        "selector2._domainkey",
        "mta-sts",
        "sip",
        "lyncdiscover",
        "mail",
        "ftp",
        "blog",
        "flightblog",
    ],
}

DOMAIN_DETAIL_DESCRIPTIONS = {
    "A": "Linking a name to an IPv4 address.",
    "AAAA": "Linking a name to an IPv6 address.",
    "CNAME": "Linking a name to another name record",
    "TXT": "Stores text values used for verification, policy, and service configuration, including SPF and common scoped TXT records.",
    "SPF": "Shows SPF policies found in TXT records, listing which senders may send mail for this domain.",
    "NS": "Lists the authoritative name servers for this domain.",
    "MX": "Lists mail servers that receive email for this domain, ordered by priority.",
    "SOA": "Shows the start-of-authority data for this DNS zone.",
    "CAA": "Controls which certificate authorities may issue TLS certificates for this domain.",
    "DS": "Delegation signer records connect this domain to DNSSEC validation in the parent zone.",
    "DNSKEY": "Public DNSSEC keys used to validate signed DNS records in this zone.",
}

def decode_dns_text(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)

def format_soa_email(value):
    email = clean_dns_name(value)
    if "." not in email:
        return email
    local, domain = email.split(".", 1)
    return f"{local}@{domain}"

def format_duration(seconds):
    try:
        seconds = int(seconds)
    except (TypeError, ValueError):
        return None

    if seconds <= 0:
        return "0s"

    units = [
        ("d", 86400),
        ("h", 3600),
        ("m", 60),
        ("s", 1),
    ]
    parts = []
    remaining = seconds
    for label, size in units:
        amount, remaining = divmod(remaining, size)
        if amount:
            parts.append(f"{amount}{label}")
        if len(parts) == 2:
            break
    return " ".join(parts)

def serialize_domain_detail_record(record, record_type):
    if record_type in ("A", "AAAA"):
        address = str(record)
        return {
            "value": address,
            "fields": {"Address": address},
        }

    if record_type == "CNAME":
        target = clean_dns_name(record.target)
        return {
            "value": target,
            "fields": {"Canonical name": target},
        }

    if record_type == "TXT":
        value = "".join(decode_dns_text(part) for part in record.strings)
        return {
            "value": value,
            "fields": {"Text": value},
        }

    if record_type == "NS":
        target = clean_dns_name(record.target)
        return {
            "value": target,
            "fields": {"Name server": target},
        }

    if record_type == "MX":
        exchange = clean_dns_name(record.exchange)
        value = f"{record.preference} {exchange}"
        return {
            "value": value,
            "fields": {},
        }

    if record_type == "SOA":
        authority = clean_dns_name(record.mname)
        fields = {
            "Start of authority": authority,
            "Email": format_soa_email(record.rname),
            "Serial": record.serial,
            "Refresh": format_duration(record.refresh),
            "Retry": format_duration(record.retry),
            "Expire": format_duration(record.expire),
            "Negative cache TTL": format_duration(record.minimum),
        }
        return {
            "value": authority,
            "fields": fields,
        }

    if record_type == "CAA":
        caa_tag = decode_dns_text(record.tag)
        caa_value = decode_dns_text(record.value)
        display = f"{record.flags} {caa_tag} {caa_value}"
        return {
            "value": display,
            "fields": {
                "Flags": record.flags,
                "Tag": caa_tag,
                "Value": caa_value,
            },
        }

    value = str(record)
    return {
        "value": value,
        "fields": {"Value": value},
    }

def with_domain_detail_record_context(record, name, ttl=None):
    record["name"] = name
    if ttl is not None:
        record["ttl"] = ttl
        record["ttl_display"] = format_duration(ttl)
    return record

def empty_domain_detail_section(record_type, message=None, name=None):
    return {
        "type": record_type,
        "description": DOMAIN_DETAIL_DESCRIPTIONS.get(record_type, ""),
        "records": [],
        "ttl": None,
        "ttl_display": None,
        "name": name,
        "message": message or f"No {record_type} records found.",
    }

def build_dns_failure_domain_details_payload(domain, message):
    return {
        "domain": domain,
        "sections": [
            empty_domain_detail_section(record_type, message, name=domain)
            for record_type in DOMAIN_DETAIL_RECORD_TYPES
        ],
    }

def resolve_domain_detail_section(domain, record_type, display_type=None):
    section_type = display_type or record_type
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=5)
        ttl = getattr(getattr(answers, "rrset", None), "ttl", None)
        return {
            "type": section_type,
            "description": DOMAIN_DETAIL_DESCRIPTIONS.get(section_type, ""),
            "records": [
                with_domain_detail_record_context(serialize_domain_detail_record(record, record_type), domain, ttl)
                for record in answers
            ],
            "ttl": ttl,
            "ttl_display": format_duration(ttl),
            "name": domain,
            "message": None,
        }
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return empty_domain_detail_section(section_type, name=domain)
    except Exception as e:
        return empty_domain_detail_section(section_type, str(e), name=domain)

def get_configured_domain_detail_names(record_type):
    configured = os.environ.get(f"DOMAIN_DETAIL_EXTRA_{record_type}_NAMES", "")
    names = []
    seen = set()

    for name in DOMAIN_DETAIL_DISCOVERY_NAMES.get(record_type, []) + configured.split(","):
        clean_name = clean_dns_name(name.strip())
        key = clean_name.lower()
        if clean_name and key not in seen:
            names.append(clean_name)
            seen.add(key)

    return names

def append_discovered_domain_detail_records(section, domain, record_type):
    existing_names = {record.get("name") for record in section.get("records", [])}

    for relative_name in get_configured_domain_detail_names(record_type):
        record_name = f"{relative_name}.{domain}"
        if record_name in existing_names:
            continue

        try:
            answers = dns.resolver.resolve(record_name, record_type, lifetime=4)
            ttl = getattr(getattr(answers, "rrset", None), "ttl", None)
            for answer in answers:
                section["records"].append(
                    with_domain_detail_record_context(
                        serialize_domain_detail_record(answer, record_type),
                        record_name,
                        ttl
                    )
                )
            existing_names.add(record_name)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except Exception:
            continue

    if section.get("records"):
        section["message"] = None
    return section

def build_spf_detail_section(txt_section):
    records = []
    for record in txt_section.get("records", []):
        value = record.get("value", "")
        if value.strip().lower().startswith("v=spf1"):
            records.append({
                "value": value,
                "fields": {"Policy": value},
            })

    section = {
        "type": "SPF",
        "description": DOMAIN_DETAIL_DESCRIPTIONS["SPF"],
        "records": records,
        "ttl": txt_section.get("ttl") if records else None,
        "ttl_display": txt_section.get("ttl_display") if records else None,
        "name": txt_section.get("name"),
        "message": None if records else "No SPF policy found in TXT records.",
    }
    return section

def clean_dns_name(value):
    return str(value).rstrip(".")

def make_record(status, value, advisories=None, level=None, **extra):
    advisories = advisories or []
    record = {
        "status": status,
        "value": value,
        "advisories": advisories,
        "level": level or ("warning" if status and advisories else "success" if status else "error")
    }
    record.update(extra)
    return record

def semicolon_spacing_advisories(records):
    advisories = []
    for record in records:
        if re.search(r";(?=\S)", record):
            advisories.append("Add a space after each semicolon before the next configuration setting.")
            break
    return advisories

def extract_tag_value(record, tag):
    match = re.search(rf"(?:^|;)\s*{re.escape(tag)}=([^;]+)", record, re.IGNORECASE)
    return match.group(1).strip().lower() if match else None

def serialize_whois_value(value):
    if value is None or value == "":
        return None
    if isinstance(value, list):
        cleaned = [serialize_whois_value(v) for v in value]
        return [v for v in cleaned if v]
    if isinstance(value, (datetime,)):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return str(value)

def get_whois_field(whois_data, *names):
    for name in names:
        value = serialize_whois_value(getattr(whois_data, name, None))
        if value:
            return value
    return None

WHOIS_FIELDS = [
    "domain_name",
    "registrar",
    "whois_server",
    "creation_date",
    "updated_date",
    "expiration_date",
    "name",
    "organization",
    "address",
    "city",
    "state",
    "zipcode",
    "country",
    "emails",
    "phone",
    "administrative_contact",
    "status",
]

def normalize_domain_availability_message(domain, message):
    text = str(message or "").strip()
    if not text:
        return None
    if re.search(r"\b(is free|available for registration|not found)\b", text, re.IGNORECASE):
        return "This domain is free and available for registration."
    return text

def empty_whois_payload(domain, lookup_status="no_public_details", lookup_message=None):
    payload = {field: None for field in WHOIS_FIELDS}
    payload["domain_name"] = domain
    payload["lookup_status"] = lookup_status
    payload["lookup_message"] = lookup_message or "No public WHOIS details found."
    if lookup_status == "available":
        payload["status"] = "Available for registration"
    return payload

def has_public_whois_details(payload):
    return any(payload.get(field) for field in WHOIS_FIELDS if field != "domain_name")

def get_rdap_availability_message(domain):
    try:
        response = requests.get(
            f"https://rdap.org/domain/{domain}",
            headers={"Accept": "application/rdap+json, application/json", "User-Agent": "DNSMegaTool/1.0"},
            timeout=6
        )
        if response.status_code != 404:
            return None
        try:
            rdap_data = response.json()
            description = " ".join(rdap_data.get("description", []))
            message = description or rdap_data.get("title")
        except Exception:
            message = response.text
        return normalize_domain_availability_message(domain, message)
    except Exception:
        return None

def build_whois_payload(domain, whois_data, administrative_contacts):
    payload = {
        "domain_name": get_whois_field(whois_data, "domain_name") or domain,
        "registrar": get_whois_field(whois_data, "registrar"),
        "whois_server": get_whois_field(whois_data, "whois_server"),
        "creation_date": get_whois_field(whois_data, "creation_date"),
        "updated_date": get_whois_field(whois_data, "updated_date"),
        "expiration_date": get_whois_field(whois_data, "expiration_date"),
        "name": get_whois_field(whois_data, "name", "registrant_name"),
        "organization": get_whois_field(whois_data, "org", "organization", "registrant_organization"),
        "address": get_whois_field(whois_data, "address", "registrant_street"),
        "city": get_whois_field(whois_data, "city", "registrant_city"),
        "state": get_whois_field(whois_data, "state", "registrant_state"),
        "zipcode": get_whois_field(whois_data, "zipcode", "registrant_postal_code"),
        "country": get_whois_field(whois_data, "country", "registrant_country"),
        "emails": get_whois_field(whois_data, "emails", "email"),
        "phone": get_whois_field(whois_data, "phone", "registrant_phone"),
        "administrative_contact": administrative_contacts,
        "status": get_whois_field(whois_data, "status"),
        "lookup_status": "found",
        "lookup_message": None,
    }

    if has_public_whois_details(payload):
        return payload

    availability_message = get_rdap_availability_message(domain)
    if availability_message:
        return empty_whois_payload(domain, "available", availability_message)

    return empty_whois_payload(domain)

def lookup_whois_data(domain):
    stream = io.StringIO()
    with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
        return whois.whois(domain)

def get_vcard_value(vcard_entries, key):
    values = []
    for entry in vcard_entries:
        if len(entry) >= 4 and entry[0].lower() == key.lower() and entry[3]:
            values.append(entry[3])
    if not values:
        return None
    return values if len(values) > 1 else values[0]

def get_rdap_administrative_contacts(domain):
    contacts = []
    try:
        response = requests.get(
            f"https://rdap.org/domain/{domain}",
            headers={"Accept": "application/rdap+json, application/json", "User-Agent": "DNSMegaTool/1.0"},
            timeout=6
        )
        response.raise_for_status()
        rdap_data = response.json()
    except Exception:
        rdap_data = {}

    for entity in rdap_data.get("entities", []):
        roles = [role.lower() for role in entity.get("roles", [])]
        if "administrative" not in roles:
            continue

        vcard = entity.get("vcardArray", [])
        vcard_entries = vcard[1] if len(vcard) > 1 and isinstance(vcard[1], list) else []
        contact = {
            "handle": entity.get("handle"),
            "name": get_vcard_value(vcard_entries, "fn"),
            "organization": get_vcard_value(vcard_entries, "org"),
            "email": get_vcard_value(vcard_entries, "email"),
            "phone": get_vcard_value(vcard_entries, "tel"),
            "address": get_vcard_value(vcard_entries, "adr"),
        }
        clean_contact = {key: serialize_whois_value(value) for key, value in contact.items() if serialize_whois_value(value)}
        if clean_contact:
            contacts.append(clean_contact)

    if contacts:
        return contacts

    try:
        page = requests.get(f"https://who.is/rdap/{domain}", timeout=6).text
        normalized = page.replace("<!-- -->", "")
        match = re.search(r"Administrative\s*Contact</h3>(.*?)(?:<h3|</div></div></div>)", normalized, re.IGNORECASE | re.DOTALL)
        if not match:
            return None
        section = match.group(1)
        pairs = re.findall(r"<dt[^>]*>(.*?)</dt>\s*<dd[^>]*>(.*?)</dd>", section, re.IGNORECASE | re.DOTALL)
        contact = {}
        for label, value in pairs:
            clean_label = re.sub(r"<.*?>", "", label).strip().lower().replace(" ", "_")
            clean_value = html.unescape(re.sub(r"<.*?>", "", value)).strip()
            clean_value = clean_value.replace(" [at] ", "@").replace(" [dot] ", ".")
            if clean_label and clean_value:
                contact[clean_label] = clean_value
        return [contact] if contact else None
    except Exception:
        return None

def make_certificate_check(status, level, line, advisories=None, days_left=None, expires_at=None):
    return {
        "status": status,
        "level": level,
        "line": line,
        "advisories": advisories or [],
        "days_left": days_left,
        "expires_at": expires_at,
    }

def check_mail_certificate_for_host(mx_host):
    mx_host = clean_dns_name(mx_host)
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(mx_host, 25, timeout=7) as smtp:
            smtp.ehlo()
            if not smtp.has_extn("starttls"):
                return make_certificate_check(
                    False,
                    "error",
                    "SSL certificate: invalid, STARTTLS not supported (0 days left)"
                )
            smtp.starttls(context=context)
            smtp.ehlo()
            cert = smtp.sock.getpeercert()

        not_after = cert.get("notAfter")
        if not not_after:
            return make_certificate_check(
                False,
                "error",
                "SSL certificate: invalid, expiry date not available (0 days left)"
            )

        expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        seconds_left = (expires_at - now).total_seconds()
        days_left = max(0, int(seconds_left // 86400))

        if seconds_left <= 0:
            level = "error"
            valid = False
        elif days_left <= 30:
            level = "warning"
            valid = True
        else:
            level = "success"
            valid = True

        valid_label = "valid" if valid else "invalid"
        expiry_label = expires_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        return make_certificate_check(
            valid,
            level,
            f"SSL certificate: {valid_label} until {expiry_label} ({days_left} days left)",
            days_left=days_left,
            expires_at=expiry_label
        )
    except ssl.SSLCertVerificationError as e:
        return make_certificate_check(
            False,
            "error",
            "SSL certificate: invalid, verification failed (0 days left)",
            [f"SSL certificate verification failed for {mx_host}: {str(e)}"]
        )
    except (socket.timeout, TimeoutError):
        return make_certificate_check(
            False,
            "error",
            "SSL certificate: unavailable, SMTP TLS check timed out (0 days left)",
            [f"SMTP TLS certificate check timed out for {mx_host} on port 25"]
        )
    except socket.gaierror:
        return make_certificate_check(
            False,
            "error",
            "SSL certificate: unavailable, MX host IP address could not be resolved (0 days left)",
            [f"MX host does not resolve to an IP address: {mx_host}"]
        )
    except smtplib.SMTPException as e:
        return make_certificate_check(
            False,
            "error",
            "SSL certificate: unavailable, SMTP TLS check failed (0 days left)",
            [f"SMTP TLS certificate check failed for {mx_host}: {str(e)}"]
        )
    except Exception as e:
        return make_certificate_check(
            False,
            "error",
            "SSL certificate: unavailable, check failed (0 days left)",
            [str(e)]
        )

def check_mail_certificates(mx_hosts):
    checks = {}
    for mx_host in mx_hosts:
        checks[clean_dns_name(mx_host)] = check_mail_certificate_for_host(mx_host)
    return checks

def get_mail_certificate_status(mx_hosts):
    if not mx_hosts:
        return make_record(False, "No MX host available for certificate check")

    checks = check_mail_certificates([mx_hosts[0]])
    check = checks.get(clean_dns_name(mx_hosts[0]))
    return make_record(
        check["status"],
        [check["line"]],
        check["advisories"],
        level=check["level"]
    )

def evaluate_spf(spf_records):
    advisories = semicolon_spacing_advisories(spf_records)
    if len(spf_records) > 1:
        advisories.append("Multiple SPF records found. Publish exactly one SPF record.")

    combined = " ".join(spf_records).lower()
    if "-all" in combined:
        return make_record(True, spf_records, advisories)
    if "~all" in combined:
        advisories.append("Softfail (~all) is being used, which means less security than hardfail (-all). Change the SPF policy to hardfail to show as succesful.")
        return make_record(True, spf_records, advisories, level="warning")
    if "?all" in combined or "+all" in combined:
        advisories.append("SPF uses a permissive all mechanism. Use -all for a strict policy.")
        return make_record(False, spf_records, advisories)

    advisories.append("SPF does not end with an all mechanism. Add -all for a strict policy.")
    return make_record(False, spf_records, advisories)

def evaluate_dmarc(dmarc_records, extra_advisories=None):
    advisories = (extra_advisories or []) + semicolon_spacing_advisories(dmarc_records)
    if len(dmarc_records) > 1:
        advisories.append("Multiple DMARC records found. Publish exactly one DMARC TXT record on _dmarc.")
    policy = None
    for record in dmarc_records:
        if record.strip().lower().startswith("v=dmarc1"):
            policy = extract_tag_value(record, "p")
            break

    if policy == "reject":
        return make_record(True, dmarc_records, advisories)
    if policy == "quarantine":
        advisories.append("DMARC uses the quarantine policy, which means less security than reject. Change the DMARC policy to reject to show as succesful.")
        return make_record(True, dmarc_records, advisories, level="warning")
    if policy == "none":
        advisories.append("DMARC policy is p=none. This is monitor-only and does not protect against spoofing. Use p=reject for enforcement.")
        return make_record(False, dmarc_records, advisories, level="error")

    advisories.append("DMARC policy tag p= was not found. Add p=reject, p=quarantine, or p=none.")
    return make_record(False, dmarc_records, advisories)

def evaluate_tls_rpt(tls_rpt_records, tls_rpt_domain, extra_advisories=None):
    if not tls_rpt_records:
        return make_record(
            False,
            record_not_found("TLS-RPT", tls_rpt_domain),
            extra_advisories or ["Publish a TLS-RPT record to receive reports about possible deliverability errors to pass this check."],
            level="warning"
        )

    advisories = (extra_advisories or []) + semicolon_spacing_advisories(tls_rpt_records)
    if len(tls_rpt_records) > 1:
        advisories.append("Multiple TLS-RPT records found. Publish exactly one TLS-RPT TXT record on _smtp._tls.")
    has_rua = any(extract_tag_value(record, "rua") for record in tls_rpt_records)

    if not has_rua:
        advisories.append("TLS-RPT record should include a rua= reporting destination.")

    return make_record(has_rua, tls_rpt_records, advisories)

def check_tlsa(mx_hosts):
    dane_results = []
    dane_valid = False
    for mx_host in mx_hosts:
        tlsa_domain = f"_25._tcp.{mx_host}"
        try:
            tlsa_records = dns.resolver.resolve(tlsa_domain, "TLSA")
            values = [str(record) for record in tlsa_records]
            if values:
                dane_valid = True
                dane_results.append(f"{tlsa_domain}: {', '.join(values)}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            dane_results.append(f"{tlsa_domain}: TLSA record not found")
        except Exception as e:
            dane_results.append(f"{tlsa_domain}: {str(e)}")

    return make_record(dane_valid, dane_results if dane_results else "No MX host available for DANE check")

def extract_mta_sts_policy_mode(policy_text):
    if not policy_text:
        return None
    match = re.search(r"^\s*mode\s*:\s*([^\s#]+)", policy_text, re.IGNORECASE | re.MULTILINE)
    return match.group(1).strip().lower() if match else None

def evaluate_mta_sts(domain, mta_sts_txt, dns_ok, https_ok, policy_url, policy_text=None, skipped=False, skip_note=None, extra_advisories=None):
    if skipped:
        return make_record(True, [skip_note], level="success", skipped=True)

    advisories = (extra_advisories or []) + semicolon_spacing_advisories([mta_sts_txt] if mta_sts_txt else [])
    valid_version = bool(mta_sts_txt and mta_sts_txt.lower().startswith("v=stsv1"))
    has_id = bool(mta_sts_txt and extract_tag_value(mta_sts_txt, "id"))
    policy_mode = extract_mta_sts_policy_mode(policy_text)

    if not valid_version:
        advisories.append("MTA-STS TXT record must start with v=STSv1.")
    if not has_id:
        advisories.append("MTA-STS TXT record should include an id= value.")
    if not https_ok:
        advisories.append("MTA-STS policy file could not be reached over HTTPS.")
    elif policy_mode != "enforce":
        advisories.append("Use enforce as the MTA-STS policy mode to pass this check.")

    values = []
    if mta_sts_txt:
        details = [
            f"Website found: {'yes' if https_ok else 'no'}",
            f"Policy mode: {policy_mode or 'not found'}",
        ]
        if policy_url:
            details.append(policy_url)
        values.append({
            "text": mta_sts_txt,
            "details": details,
        })

    base_status = dns_ok and https_ok and valid_version and has_id
    level = "warning" if base_status and policy_mode != "enforce" else None
    return make_record(base_status, values, advisories, level=level)

@app.route(route="domain-details")
def domain_details(req: func.HttpRequest) -> func.HttpResponse:
    domain = req.params.get("domain")
    if not domain:
        return func.HttpResponse("Please pass a domain on the query string", status_code=400)

    domain = clean_dns_name(domain.strip().lower())
    if not re.match(r"^(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,}$", domain):
        return func.HttpResponse("Please pass a valid domain", status_code=400)

    dns_failure = get_domain_dns_resolution_failure(domain)
    if dns_failure:
        return func.HttpResponse(
            json.dumps(build_dns_failure_domain_details_payload(domain, dns_failure)),
            mimetype="application/json"
        )

    sections_by_type = {}
    for record_type in DOMAIN_DETAIL_RECORD_TYPES:
        section = resolve_domain_detail_section(domain, record_type)
        if record_type in DOMAIN_DETAIL_DISCOVERY_NAMES:
            section = append_discovered_domain_detail_records(section, domain, record_type)
        sections_by_type[record_type] = section

    sections = []
    for record_type in DOMAIN_DETAIL_RECORD_TYPES:
        section = sections_by_type[record_type]
        sections.append(section)

    payload = {
        "domain": domain,
        "sections": sections,
    }
    return func.HttpResponse(json.dumps(payload), mimetype="application/json")

@app.route(route="lookup")
def dns_lookup(req: func.HttpRequest) -> func.HttpResponse:
    domain = req.params.get('domain')
    if not domain:
        return func.HttpResponse("Please pass a domain on the query string", status_code=400)

    domain = clean_dns_name(domain.strip().lower())
    if not re.match(r"^(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,}$", domain):
        return func.HttpResponse("Please pass a valid domain", status_code=400)

    dns_failure = get_domain_dns_resolution_failure(domain)
    if dns_failure:
        return func.HttpResponse(
            json.dumps(build_dns_failure_lookup_payload(domain, dns_failure)),
            mimetype="application/json"
        )

    results = {}
    mx_hosts = []

    # MX lookup
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_records = sorted(mx_records, key=lambda r: r.preference)
        mx_hosts = [clean_dns_name(r.exchange) for r in mx_records]
        mx_certificate_checks = check_mail_certificates(mx_hosts)
        mx_values, mx_blacklist_advisories, mx_blacklist_total, unresolved_mx_hosts = check_mx_blacklists(mx_hosts, mx_certificate_checks)
        mx_certificate_advisories = []
        mx_certificate_level = None
        for certificate_check in mx_certificate_checks.values():
            mx_certificate_advisories.extend(certificate_check["advisories"])
            mx_certificate_level = worse_level(mx_certificate_level, certificate_check["level"])
        mx_valid = len(mx_records) > 0 and not unresolved_mx_hosts
        mx_level = worse_level(
            "error" if unresolved_mx_hosts else None,
            "warning" if mx_blacklist_total > 0 else None,
            mx_certificate_level
        )
        results['MX'] = make_record(
            mx_valid and mx_certificate_level != "error",
            mx_values if mx_values else mx_hosts,
            mx_blacklist_advisories + mx_certificate_advisories,
            level=mx_level
        )
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        results['MX'] = make_record(False, record_not_found("MX", domain))
    except Exception as e:
        results['MX'] = make_record(False, str(e))

    # SPF lookup (TXT record)
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        spf_records = []
        for r in txt_records:
            full_record = ''.join([b.decode('utf-8') for b in r.strings])
            if full_record.startswith('v=spf1'):
                spf_records.append(full_record)

        if spf_records:
            results['SPF'] = evaluate_spf(spf_records)
        else:
            results['SPF'] = make_record(False, record_not_found("SPF", domain), ["Publish an SPF record that lists all legitimate sending services."])
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        results['SPF'] = make_record(False, record_not_found("SPF", domain), ["Publish an SPF record that lists all legitimate sending services."])
    except Exception as e:
        results['SPF'] = make_record(False, str(e))

    # DKIM lookup
    # Microsoft 365 normally publishes selector1/selector2 as CNAME records.
    # Other providers often publish a DKIM public key directly as TXT under a
    # provider-specific selector. DNS has no generic operation to enumerate all
    # selector names, so in addition to selector1/selector2 we probe a curated set
    # of common selector names and return every v=DKIM1 TXT value found there.
    try:
        primary_selectors = ["selector1", "selector2"]
        common_selectors = [
            "default", "google", "dkim", "mail", "smtp",
            "s1", "s2", "k1", "k2", "mta",
            "mandrill", "amazonses", "zoho", "zmail", "protonmail"
        ]

        # Deployments can add extra known selectors without changing the code.
        configured_extra_selectors = [
            selector.strip().lower()
            for selector in os.environ.get("DKIM_EXTRA_SELECTORS", "").split(",")
            if selector.strip()
        ]
        extra_selectors = []
        for selector in common_selectors + configured_extra_selectors:
            if selector not in primary_selectors and selector not in extra_selectors:
                extra_selectors.append(selector)

        dkim_advisories = []
        primary_states = {}
        microsoft_365_detected = False
        additional_dkim_found = False

        def is_microsoft_365_dkim_target(target):
            target = clean_dns_name(target).lower()
            # Current Microsoft DKIM infrastructure uses dkim.mail.microsoft.
            # Legacy Microsoft 365 DKIM CNAME targets can reference onmicrosoft.com.
            return (
                target.endswith(".dkim.mail.microsoft")
                or "._domainkey." in target and target.endswith(".onmicrosoft.com")
            )

        def get_dkim_txt_values(name):
            try:
                answers = dns.resolver.resolve(name, "TXT")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                return []
            values = txt_record_values(answers)
            return [value for value in values if value.strip().lower().startswith("v=dkim1")]

        def inspect_selector(selector):
            selector_domain = f"{selector}._domainkey.{domain}"
            state = {
                "selector": selector,
                "name": selector_domain,
                "record_exists": False,
                "record_type": None,
                "cname_target": None,
                "dkim_values": [],
                "key_published": False,
                "microsoft_365": False,
                "lookup_warning": None,
            }

            # First inspect the published CNAME itself. This makes it possible to
            # distinguish 'record exists but target key is not published' from
            # 'selector record does not exist'.
            try:
                cname_answers = dns.resolver.resolve(selector_domain, "CNAME")
                cname_targets = [clean_dns_name(answer.target) for answer in cname_answers]
                if cname_targets:
                    state["record_exists"] = True
                    state["record_type"] = "CNAME"
                    state["cname_target"] = cname_targets[0]
                    state["microsoft_365"] = is_microsoft_365_dkim_target(cname_targets[0])
                    try:
                        state["dkim_values"] = get_dkim_txt_values(cname_targets[0])
                        state["key_published"] = bool(state["dkim_values"])
                    except Exception as exc:
                        state["lookup_warning"] = f"DKIM target TXT lookup failed: {exc}"
                    return state
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except Exception as exc:
                state["lookup_warning"] = f"CNAME lookup failed: {exc}"

            # If no CNAME exists, check whether this selector publishes DKIM
            # directly as TXT (common outside Microsoft 365).
            try:
                dkim_values = get_dkim_txt_values(selector_domain)
                if dkim_values:
                    state["record_exists"] = True
                    state["record_type"] = "TXT"
                    state["dkim_values"] = dkim_values
                    state["key_published"] = True
            except Exception as exc:
                previous = state["lookup_warning"]
                state["lookup_warning"] = (previous + "; " if previous else "") + f"TXT lookup failed: {exc}"

            return state

        def build_selector_section(state):
            if state["dkim_values"]:
                values = state["dkim_values"]
            elif state["record_exists"]:
                values = ["DKIM key not found"]
            else:
                values = []
            details = []

            if state["record_exists"]:
                if state["record_type"] == "CNAME":
                    record_label = "CNAME record found"
                else:
                    record_label = "TXT record found"
                key_label = "DKIM key found" if state["key_published"] else "DKIM key not found behind this record"
                details.append(f"{record_label} | {key_label}")
            else:
                details.append(f"DNS record not found | DKIM key not found")

            return {
                "selector": state["selector"],
                "values": values,
                "details": details,
                "record_exists": state["record_exists"],
                "record_type": state["record_type"],
                "key_published": state["key_published"],
            }

        dkim_sections = []
        additional_sections = []

        def add_additional_dkim_section(state):
            section = build_selector_section(state)
            section["original_selector"] = section["selector"]
            section["selector"] = f"DKIM{len(additional_sections) + 1}"
            section["details"] = []
            additional_sections.append(section)

        # selector1 and selector2 get explicit status reporting because Microsoft
        # 365 requires both selector CNAMEs to be configured.
        for selector in primary_selectors:
            state = inspect_selector(selector)
            primary_states[selector] = state
            microsoft_365_detected = microsoft_365_detected or state["microsoft_365"]

            if state["lookup_warning"]:
                dkim_advisories.append(f"{selector}: {state['lookup_warning']}")

        for selector in primary_selectors:
            state = primary_states[selector]
            display_state = state.copy()

            if not microsoft_365_detected and state["record_type"] == "TXT" and state["dkim_values"]:
                additional_dkim_found = True
                add_additional_dkim_section(state)
                display_state.update({
                    "record_exists": False,
                    "record_type": None,
                    "dkim_values": [],
                    "key_published": False,
                })

            dkim_sections.append(build_selector_section(display_state))

        # Look for non-Microsoft DKIM records using common selectors. Every TXT
        # value beginning with v=DKIM1 is returned; we do not stop after the first.
        for selector in extra_selectors:
            state = inspect_selector(selector)
            if state["record_exists"] and state["dkim_values"]:
                additional_dkim_found = True
                add_additional_dkim_section(state)

        selector1_ok = primary_states["selector1"]["record_type"] == "CNAME" and primary_states["selector1"]["key_published"]
        selector2_ok = primary_states["selector2"]["record_type"] == "CNAME" and primary_states["selector2"]["key_published"]
        primary_ok_count = int(selector1_ok) + int(selector2_ok)
        primary_record_count = int(primary_states["selector1"]["record_type"] == "CNAME") + int(primary_states["selector2"]["record_type"] == "CNAME")
        primary_cname_count = int(primary_states["selector1"]["record_type"] == "CNAME") + int(primary_states["selector2"]["record_type"] == "CNAME")
        dkim_value = {
            "kind": "dkim",
            "microsoft_365": microsoft_365_detected,
            "sections": dkim_sections,
            "additional_sections": additional_sections,
        }

        if microsoft_365_detected:
            # A missing public key on one selector is intentionally a warning, not
            # a hard failure. The selector CNAME may be correctly configured while
            # Microsoft has no current key published behind the standby selector.
            if primary_ok_count < 2:
                command = f"Rotate-DkimSigningConfig -Identity {domain}"
                dkim_value["action"] = {
                    "command": command,
                    "url": "https://security.microsoft.com/dkimv2",
                    "message": "After confirming both selector CNAME records are correct, rotate the DKIM signing configuration:",
                }
                dkim_advisories.append(
                    f"One or more Microsoft 365 DKIM selector keys are not currently published. "
                    f"After confirming both selector CNAME records are correct, rotate the DKIM signing configuration with: {command}"
                )

            # Missing Microsoft 365 selector CNAME records are configuration errors.
            # Published CNAMEs with missing target keys are warnings, so users can
            # distinguish DNS setup issues from unpublished Microsoft-side keys.
            if primary_cname_count < 2:
                results["DKIM"] = make_record(False, dkim_value, dkim_advisories, level="error")
            elif primary_ok_count < 2:
                results["DKIM"] = make_record(True, dkim_value, dkim_advisories, level="warning")
            else:
                results["DKIM"] = make_record(True, dkim_value, dkim_advisories)
        else:
            # Non-Microsoft 365: selector1/selector2 are not requirements. A DKIM
            # TXT key found on any checked selector is sufficient to mark DKIM as
            # present. If only one of selector1/selector2 is found, keep the result
            # orange as requested rather than failing it.
            any_dkim_key = primary_ok_count > 0 or additional_dkim_found
            if any_dkim_key:
                if primary_record_count == 0 and additional_dkim_found:
                    dkim_advisories.append("selector1 and selector2 are not configured, but a DKIM key was found on another selector.")
                    results["DKIM"] = make_record(True, dkim_value, dkim_advisories, level="warning")
                elif primary_ok_count == 1 and not additional_dkim_found:
                    dkim_advisories.append("Only one of selector1/selector2 has a published DKIM key.")
                    results["DKIM"] = make_record(True, dkim_value, dkim_advisories, level="warning")
                else:
                    results["DKIM"] = make_record(True, dkim_value, dkim_advisories)
            else:
                dkim_advisories.append(
                    "No DKIM key was found on selector1, selector2, or the built-in common-selector scan. "
                    "DNS does not provide a standard way to enumerate every possible DKIM selector name."
                )
                results["DKIM"] = make_record(False, dkim_value, dkim_advisories, level="error")
    except Exception as e:
        results['DKIM'] = make_record(False, str(e))

    # DMARC lookup
    dmarc_domain = "_dmarc." + domain
    try:
        dmarc_scoped = resolve_scoped_txt(dmarc_domain, "v=DMARC1")
        dmarc_advisories = scoped_txt_advisories(
            "DMARC",
            dmarc_scoped,
            "Publish a DMARC record with p=reject for the strongest protection." if not dmarc_scoped["valid_records"] else None
        )
        if dmarc_scoped["valid_records"]:
            results['DMARC'] = evaluate_dmarc(dmarc_scoped["valid_records"], dmarc_advisories)
        else:
            results['DMARC'] = make_record(False, record_not_found("DMARC", dmarc_domain), dmarc_advisories)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        results['DMARC'] = make_record(False, record_not_found("DMARC", dmarc_domain), ["Publish a DMARC record with p=reject for the strongest protection."])
    except Exception as e:
        results['DMARC'] = make_record(False, str(e))

    # TLS-RPT lookup
    tls_rpt_domain = "_smtp._tls." + domain
    try:
        tls_rpt_scoped = resolve_scoped_txt(tls_rpt_domain, "v=TLSRPTv1")
        tls_rpt_advisories = scoped_txt_advisories(
            "TLS-RPT",
            tls_rpt_scoped,
            "Publish a TLS-RPT record to receive reports about possible deliverability errors to pass this check." if not tls_rpt_scoped["valid_records"] else None
        )
        results['TLS-RPT'] = evaluate_tls_rpt(tls_rpt_scoped["valid_records"], tls_rpt_domain, tls_rpt_advisories)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        results['TLS-RPT'] = make_record(False, record_not_found("TLS-RPT", tls_rpt_domain), ["Publish a TLS-RPT record to receive reports about possible deliverability errors to pass this check."], level="warning")
    except Exception as e:
        results['TLS-RPT'] = make_record(False, str(e))

    # DNSSEC lookup
    dnssec_valid = False
    try:
        ds_records = dns.resolver.resolve(domain, 'DS')
        dnssec_valid = len(ds_records) > 0
        ds_values = [str(r) for r in ds_records]
        results['DNSSEC'] = make_record(dnssec_valid, ds_values)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        results['DNSSEC'] = make_record(False, record_not_found("DNSSEC", domain), ["Enable DNSSEC at the registrar and publish DS records for this domain."])
    except Exception as e:
        results['DNSSEC'] = make_record(False, str(e))

    # DANE lookup for SMTP
    results['DANE'] = check_tlsa(mx_hosts)

    # MTA-STS lookup with validation
    try:
        has_microsoft_365_mx = any(host.lower().endswith("mx.microsoft") for host in mx_hosts)
        if has_microsoft_365_mx and dnssec_valid and results['DANE']["status"]:
            skip_note = "Skipped: Microsoft 365 MX, DNSSEC, and SMTP DANE are configured, so DANE supersedes MTA-STS for this domain."
            results['MTA-STS'] = evaluate_mta_sts(domain, None, True, True, None, skipped=True, skip_note=skip_note)
            raise StopIteration

        mta_sts_domain = "_mta-sts." + domain
        try:
            mta_sts_scoped = resolve_scoped_txt(mta_sts_domain, "v=STSv1")
            mta_sts_advisories = scoped_txt_advisories(
                "MTA-STS",
                mta_sts_scoped,
                "Publish a MTA-STS record and policy to pass this check." if not mta_sts_scoped["valid_records"] else None
            )
            if len(mta_sts_scoped["valid_records"]) > 1:
                mta_sts_advisories.append("Multiple MTA-STS TXT records found. Publish exactly one MTA-STS TXT record on _mta-sts.")

            if mta_sts_scoped["valid_records"]:
                mta_sts_dns_ok = True
                mta_sts_txt_value = mta_sts_scoped["valid_records"][0]
            else:
                mta_sts_dns_ok = False
                results['MTA-STS'] = make_record(False, record_not_found("MTA-STS", mta_sts_domain), mta_sts_advisories, level="warning")
                mta_sts_dns_ok = None  # Stop further processing
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            mta_sts_dns_ok = False
            results['MTA-STS'] = make_record(False, record_not_found("MTA-STS", mta_sts_domain), ["Publish a MTA-STS record and policy to pass this check."], level="warning")
            mta_sts_dns_ok = None  # Stop further processing

        if mta_sts_dns_ok is not None:
            policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
            mta_sts_policy_text = None
            try:
                fallback_url = f"https://{domain}/.well-known/mta-sts.txt"
                r = requests.get(policy_url, timeout=5)
                mta_sts_http_ok = r.status_code == 200
                if mta_sts_http_ok:
                    mta_sts_policy_text = r.text
                else:
                    try:
                        r2 = requests.get(fallback_url, timeout=5)
                        mta_sts_http_ok = r2.status_code == 200
                        if mta_sts_http_ok:
                            mta_sts_policy_text = r2.text
                            policy_url = fallback_url
                    except:
                        mta_sts_http_ok = False
            except:
                mta_sts_http_ok = False

            results['MTA-STS'] = evaluate_mta_sts(domain, mta_sts_txt_value, mta_sts_dns_ok, mta_sts_http_ok, policy_url, mta_sts_policy_text, extra_advisories=mta_sts_advisories)
    except StopIteration:
        pass
    except Exception as e:
        results['MTA-STS'] = make_record(False, str(e))

    # NS lookup
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        ns_list = [str(r.target) for r in ns_records]
        results['NS'] = ns_list
    except:
        results['NS'] = []

    # WHOIS lookup
    try:
        whois_data = lookup_whois_data(domain)
        administrative_contacts = get_rdap_administrative_contacts(domain)
        results['WHOIS'] = build_whois_payload(domain, whois_data, administrative_contacts)
    except Exception as e:
        availability_message = normalize_domain_availability_message(domain, str(e))
        if availability_message:
            results['WHOIS'] = empty_whois_payload(domain, "available", availability_message)
        else:
            results['WHOIS'] = empty_whois_payload(domain, "lookup_error", f"WHOIS lookup failed: {str(e)}")

    return func.HttpResponse(json.dumps(results), mimetype="application/json")
