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
from datetime import datetime, timezone

# Function settings
app = func.FunctionApp()

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

def check_mx_blacklists(mx_hosts):
    zones = get_dnsbl_zones()
    details = []
    advisories = []
    total_listed = 0

    for mx_host in mx_hosts:
        ips = resolve_mx_host_ips(mx_host)
        if not ips:
            details.append({
                "text": mx_host,
                "details": ["Blacklist check: unavailable, MX host IP address could not be resolved"],
            })
            continue

        checks = [check_ip_against_dnsbls(ip, zones) for ip in ips]
        summary = build_blacklist_summary(checks)
        total_listed += summary["listed_count"]
        advisories.extend(summary["advisories"])
        details.append({
            "text": mx_host,
            "details": [summary["line"]],
        })

    return details, advisories, total_listed

def record_not_found(record_type, domain):
    return f"{record_type} record not found: {domain}"

def txt_record_values(records):
    return ["".join([b.decode("utf-8") for b in r.strings]) for r in records]

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

def get_mail_certificate_status(mx_hosts):
    if not mx_hosts:
        return make_record(False, "No MX host available for certificate check")

    mx_host = clean_dns_name(mx_hosts[0])
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(mx_host, 25, timeout=7) as smtp:
            smtp.ehlo()
            if not smtp.has_extn("starttls"):
                return {
                    "status": False,
                    "level": "error",
                    "value": [
                        "Validity state: Invalid",
                        "Days left: 0",
                        "Valid until: Not available"
                    ]
                }
            smtp.starttls(context=context)
            smtp.ehlo()
            cert = smtp.sock.getpeercert()

        not_after = cert.get("notAfter")
        if not not_after:
            return {"status": False, "level": "error", "value": "Certificate expiry date not available"}

        expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        seconds_left = (expires_at - now).total_seconds()
        days_left = max(0, int(seconds_left // 86400))
        common_name = ""
        for subject_part in cert.get("subject", []):
            for key, value in subject_part:
                if key == "commonName":
                    common_name = value
                    break
            if common_name:
                break

        if seconds_left <= 0:
            level = "error"
            valid = False
        elif days_left <= 30:
            level = "warning"
            valid = True
        else:
            level = "success"
            valid = True

        value = [
            f"Validity state: {'Valid' if valid else 'Invalid'}",
            f"Days left: {days_left}",
            f"Valid until: {expires_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        ]

        return {
            "status": valid,
            "level": level,
            "days_left": days_left,
            "value": value
        }
    except ssl.SSLCertVerificationError as e:
        return make_record(False, [
            "Validity state: Invalid",
            "Days left: 0",
            "Valid until: Not available"
        ], [f"SSL certificate verification failed for {mx_host}: {str(e)}"])
    except (socket.timeout, TimeoutError):
        return make_record(False, [
            "Validity state: Invalid",
            "Days left: 0",
            "Valid until: Not available"
        ], [f"SMTP TLS certificate check timed out for {mx_host} on port 25"])
    except smtplib.SMTPException as e:
        return make_record(False, [
            "Validity state: Invalid",
            "Days left: 0",
            "Valid until: Not available"
        ], [f"SMTP TLS certificate check failed for {mx_host}: {str(e)}"])
    except Exception as e:
        return make_record(False, [
            "Validity state: Invalid",
            "Days left: 0",
            "Valid until: Not available"
        ], [str(e)])

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

def evaluate_dmarc(dmarc_records):
    advisories = semicolon_spacing_advisories(dmarc_records)
    policy = None
    for record in dmarc_records:
        if record.lower().startswith("v=dmarc1"):
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

def evaluate_tls_rpt(tls_rpt_records):
    advisories = semicolon_spacing_advisories(tls_rpt_records)
    valid_version = any(record.lower().startswith("v=tlsrptv1") for record in tls_rpt_records)
    has_rua = any(extract_tag_value(record, "rua") for record in tls_rpt_records)

    if not valid_version:
        advisories.append("TLS-RPT record must start with v=TLSRPTv1.")
    if not has_rua:
        advisories.append("TLS-RPT record should include a rua= reporting destination.")

    return make_record(valid_version and has_rua, tls_rpt_records, advisories)

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

def evaluate_mta_sts(domain, mta_sts_txt, dns_ok, https_ok, policy_url, skipped=False, skip_note=None):
    if skipped:
        return make_record(True, [skip_note], level="success", skipped=True)

    advisories = semicolon_spacing_advisories([mta_sts_txt] if mta_sts_txt else [])
    valid_version = bool(mta_sts_txt and mta_sts_txt.lower().startswith("v=stsv1"))
    has_id = bool(mta_sts_txt and extract_tag_value(mta_sts_txt, "id"))
    if not valid_version:
        advisories.append("MTA-STS TXT record must start with v=STSv1.")
    if not has_id:
        advisories.append("MTA-STS TXT record should include an id= value.")
    if not https_ok:
        advisories.append("MTA-STS policy file could not be reached over HTTPS.")

    values = []
    if mta_sts_txt:
        values.append(mta_sts_txt)
    values.append(f"DNS: {dns_ok}")
    values.append(f"HTTPS: {https_ok}")
    values.append(policy_url)
    return make_record(dns_ok and https_ok and valid_version and has_id, values, advisories)

@app.route(route="lookup")
def dns_lookup(req: func.HttpRequest) -> func.HttpResponse:
    domain = req.params.get('domain')
    if not domain:
        return func.HttpResponse("Please pass a domain on the query string", status_code=400)

    results = {}
    mx_hosts = []

    # MX lookup
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_records = sorted(mx_records, key=lambda r: r.preference)
        mx_hosts = [clean_dns_name(r.exchange) for r in mx_records]
        mx_valid = len(mx_records) > 0
        mx_values, mx_blacklist_advisories, mx_blacklist_total = check_mx_blacklists(mx_hosts)
        results['MX'] = make_record(
            mx_valid,
            mx_values if mx_values else mx_hosts,
            mx_blacklist_advisories,
            level="warning" if mx_blacklist_total > 0 else None
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
    try:
        selectors = ['selector1', 'selector2']
        dkim_results = []
        dkim_valid = True

        for selector in selectors:
            dkim_domain = f"{selector}._domainkey.{domain}"
            try:
                dkim_records = dns.resolver.resolve(dkim_domain, 'TXT')
                dkim_txt = [b.decode('utf-8') for r in dkim_records for b in r.strings]
                dkim_results.append(f"{selector}: {dkim_txt[0]}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                dkim_results.append(f"{selector}: DKIM record not found: {dkim_domain}")
                dkim_valid = False
            except Exception as e:
                dkim_results.append(f"{selector}: {str(e)}")
                dkim_valid = False

        results['DKIM'] = make_record(dkim_valid, dkim_results)
    except Exception as e:
        results['DKIM'] = make_record(False, str(e))

    # DMARC lookup
    try:
        dmarc_domain = "_dmarc." + domain
        dmarc_records = dns.resolver.resolve(dmarc_domain, 'TXT')
        dmarc_txt = txt_record_values(dmarc_records)

        results['DMARC'] = evaluate_dmarc(dmarc_txt)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        results['DMARC'] = make_record(False, record_not_found("DMARC", dmarc_domain), ["Publish a DMARC record with p=reject for the strongest protection."])
    except Exception as e:
        results['DMARC'] = make_record(False, str(e))

    # TLS-RPT lookup
    try:
        tls_rpt_domain = "_smtp._tls." + domain
        tls_rpt_records = dns.resolver.resolve(tls_rpt_domain, 'TXT')
        tls_rpt_txt = txt_record_values(tls_rpt_records)
        results['TLS-RPT'] = evaluate_tls_rpt(tls_rpt_txt)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        results['TLS-RPT'] = make_record(False, record_not_found("TLS-RPT", "_smtp._tls." + domain), ["Publish a TLS-RPT record to receive reports about possible deliverability errors to pass this check."], level="warning")
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
            mta_sts_records = dns.resolver.resolve(mta_sts_domain, 'TXT')
            mta_sts_dns_ok = True
            mta_sts_txt_value = ''.join([b.decode('utf-8') for b in mta_sts_records[0].strings])  # Get the TXT record value
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            mta_sts_dns_ok = False
            results['MTA-STS'] = make_record(False, record_not_found("MTA-STS", mta_sts_domain), ["Publish a MTA-STS record and policy to pass this check."], level="warning")
            mta_sts_dns_ok = None  # Stop further processing

        if mta_sts_dns_ok is not None:
            policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
            try:
                fallback_url = f"https://{domain}/.well-known/mta-sts.txt"
                r = requests.get(policy_url, timeout=5)
                mta_sts_http_ok = r.status_code == 200
                if not mta_sts_http_ok:
                    try:
                        r2 = requests.get(fallback_url, timeout=5)
                        mta_sts_http_ok = r2.status_code == 200
                    except:
                        mta_sts_http_ok = False
            except:
                mta_sts_http_ok = False

            results['MTA-STS'] = evaluate_mta_sts(domain, mta_sts_txt_value, mta_sts_dns_ok, mta_sts_http_ok, policy_url)
    except StopIteration:
        pass
    except Exception as e:
        results['MTA-STS'] = make_record(False, str(e))

    # MX SSL certificate validity lookup
    results['MX SSL'] = get_mail_certificate_status(mx_hosts)

    # NS lookup
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        ns_list = [str(r.target) for r in ns_records]
        results['NS'] = ns_list
    except:
        results['NS'] = []

    # WHOIS lookup
    try:
        whois_data = whois.whois(domain)
        administrative_contacts = get_rdap_administrative_contacts(domain)
        results['WHOIS'] = {
            "domain_name": get_whois_field(whois_data, "domain_name"),
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
            "status": get_whois_field(whois_data, "status")
        }
    except Exception as e:
        results['WHOIS'] = {"error": str(e)}

    return func.HttpResponse(json.dumps(results), mimetype="application/json")
