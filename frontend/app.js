let isLoading = false;
let currentMode = "single"; // "single" | "bulk"

const recordDescriptions = {
    "MX": "Mail Exchange records tells the internet where the server of your domain is.",
    "SPF": "Sender Policy Framework lists which servers are trusted to send email for this domain.",
    "DKIM": "DomainKeys Identified Mail uses cryptographic signatures so receivers can verify email was authorized by the sender.",
    "DMARC": "Domain-based Message Authentication, Reporting and Conformance tells receivers what to do when SPF or DKIM checks fail.",
    "TLS-RPT": "SMTP TLS Reporting publishes where mail providers should send reports about encrypted mail delivery problems.",
    "MTA-STS": "Mail Transfer Agent Strict Transport Security tells mail servers to require encrypted SMTP delivery for this domain.",
    "DNSSEC": "Domain Name System Security Extensions add signed DNS data so resolvers can detect forged DNS answers.",
    "DANE": "DNS-based Authentication of Named Entities publishes TLSA records so SMTP TLS certificates can be validated through DNSSEC.",
    "MX SSL": "Checks the SSL certificate of the MX server of your domain."
};

const recordDocumentationLinks = {
    "MX": "https://justinverstijnen.nl/enhance-email-security-with-spf-dkim-dmarc/#what-is-a-mx-record",
    "SPF": "https://justinverstijnen.nl/enhance-email-security-with-spf-dkim-dmarc/#spf---sender-policy-framework",
    "DKIM": "https://justinverstijnen.nl/enhance-email-security-with-spf-dkim-dmarc/#dkim---domain-keys-identified-mail",
    "DMARC": "https://justinverstijnen.nl/enhance-email-security-with-spf-dkim-dmarc/#dmarc---domain-based-message-authentication-reporting-and-conformance",
    "TLS-RPT": "https://justinverstijnen.nl/what-is-tls-rpt/",
    "DNSSEC": "https://justinverstijnen.nl/configure-dnssec-and-smtp-dane-with-exchange-online-microsoft-365/#domain-name-system-security-extensions-dnssec",
    "DANE": "https://justinverstijnen.nl/configure-dnssec-and-smtp-dane-with-exchange-online-microsoft-365/",
    "MTA-STS": "https://justinverstijnen.nl/what-is-mta-sts-and-how-to-protect-your-email-flow/"
};

const recordOrder = ["MX", "MX SSL", "SPF", "DKIM", "DMARC", "TLS-RPT", "DNSSEC", "DANE", "MTA-STS"];

document.addEventListener("DOMContentLoaded", function () {
    const domainInput = document.getElementById("domainInput");
    const checkBtn = document.getElementById("checkBtn");
    const bulkBtn = document.getElementById("bulkBtn");
    const exportBtn = document.getElementById("exportBtn");

    domainInput.focus();

    domainInput.addEventListener("keydown", function (event) {
        if (event.key === "Enter") {
            if (isLoading) return;
            event.preventDefault();
            checkDomain();
        }
    });

    checkBtn.addEventListener("click", function (event) {
        event.preventDefault();
        checkDomain();
    });

    if (bulkBtn) {
        bulkBtn.addEventListener("click", function (event) {
            event.preventDefault();
            openBulkModal();
        });
    }

    const bulkClose = document.getElementById("bulkClose");
    if (bulkClose) bulkClose.addEventListener("click", closeBulkModal);

    const bulkModal = document.getElementById("bulkModal");
    if (bulkModal) {
        bulkModal.addEventListener("click", function (e) {
            // close when clicking outside the dialog
            if (e.target === bulkModal) closeBulkModal();
        });
    }

    const bulkRunBtn = document.getElementById("bulkRunBtn");
    if (bulkRunBtn) bulkRunBtn.addEventListener("click", runBulkLookup);

    exportBtn.addEventListener("click", function (event) {
        event.preventDefault();
        exportReport();
    });
});

function openBulkModal() {
    const bulkModal = document.getElementById("bulkModal");
    const bulkTextarea = document.getElementById("bulkTextarea");
    if (!bulkModal || !bulkTextarea) return;

    bulkModal.style.display = "flex";
    setTimeout(() => bulkTextarea.focus(), 0);
}

function closeBulkModal() {
    const bulkModal = document.getElementById("bulkModal");
    if (!bulkModal) return;
    bulkModal.style.display = "none";
}

function normalizeDomain(input) {
    let d = (input || "").trim();
    if (!d) return "";
    // strip protocol/path if someone pastes a URL
    d = d.replace(/^https?:\/\//i, "");
    d = d.split("/")[0].trim();
    // strip trailing dot
    d = d.replace(/\.$/, "");
    return d.toLowerCase();
}

function isValidDomain(domain) {
    const domainPattern = /^(?!\-)([a-zA-Z0-9\-]{1,63}(?<!\-)\.)+[a-zA-Z]{2,}$/;
    return domainPattern.test(domain);
}

async function checkDomain() {
    isLoading = true;
    currentMode = "single";

    document.querySelector(".container")?.classList.remove("bulk-mode");

    const checkBtn = document.getElementById("checkBtn");
    const bulkBtn = document.getElementById("bulkBtn");
    const exportBtn = document.getElementById("exportBtn");

    checkBtn.disabled = true;
    if (bulkBtn) bulkBtn.disabled = true;

    let domain = normalizeDomain(document.getElementById("domainInput").value);
    document.getElementById("domainInput").value = domain;

    if (!isValidDomain(domain)) {
        alert("The input does not appear to be a valid domain. Please check your entry.");
        isLoading = false;
        checkBtn.disabled = false;
        if (bulkBtn) bulkBtn.disabled = false;
        return;
    }

    const loader = document.getElementById("loader");
    const resultsSection = document.getElementById("resultsSection");
    const bulkResultsSection = document.getElementById("bulkResultsSection");
    const tbody = document.querySelector("#resultTable tbody");
    const extraInfo = document.getElementById("extraInfo");

    // Reset views
    if (bulkResultsSection) bulkResultsSection.style.display = "none";
    resultsSection.style.display = "none";
    exportBtn.style.display = "none";
    loader.style.display = "flex";

    // Clear existing content
    tbody.innerHTML = "";
    extraInfo.innerHTML = "";

    try {
        const response = await fetch(`/api/lookup?domain=${encodeURIComponent(domain)}`);
        const data = await response.json();

        // Fill the table
        for (const type of recordOrder) {
            const record = data[type];
            if (!record || record.skipped) continue;
            record.type = type;

            const row = document.createElement("tr");
            row.className = `status-row row-${getStatusLevel(record)}`;
            const typeCell = document.createElement("td");
            typeCell.appendChild(createRecordTypeLabel(type));

            const statusCell = document.createElement("td");
            statusCell.appendChild(createStatusIcon(record));

            const valueCell = document.createElement("td");
            appendRecordDetails(valueCell, record);

            row.appendChild(typeCell);
            row.appendChild(valueCell);
            row.appendChild(statusCell);
            tbody.appendChild(row);
        }

        // Confetti if all green
        let allGreen = true;
        for (const type of recordOrder) {
            const record = data[type];
            if (!record || record.skipped) continue;
            if (!record.status || getStatusLevel(record) !== "success") {
                allGreen = false;
                break;
            }
        }
        if (allGreen && typeof confetti === "function") {
            confetti({
                particleCount: 300,
                spread: 200,
                origin: { y: 0.6 },
            });
        }

        // Extra info: Nameservers (API returns an array)
        if (data.NS) {
            const nsBox = document.createElement("div");
            nsBox.className = "infobox";
            const listItems = Array.isArray(data.NS) ? data.NS.map((ns) => `<li>${ns}</li>`).join("") : "";
            nsBox.innerHTML = `<h3>Nameservers for ${domain}:</h3><ul>${listItems}</ul>`;
            extraInfo.appendChild(nsBox);
        }

        // Extra info: WHOIS (API returns registrar/contact/date fields or error)
        if (data.WHOIS) {
            const whoisBox = document.createElement("div");
            whoisBox.className = "infobox";

            const whoisTitle = document.createElement("h3");
            whoisTitle.textContent = `WHOIS Information for ${domain}:`;
            whoisBox.appendChild(whoisTitle);

            if (data.WHOIS.error) {
                const errorText = document.createElement("p");
                errorText.textContent = data.WHOIS.error;
                whoisBox.appendChild(errorText);
            } else {
                whoisBox.appendChild(createWhoisList(data.WHOIS));
            }

            extraInfo.appendChild(whoisBox);
        }
    } catch (e) {
        console.error(e);
        alert("The domain could not be found because of an error. The application is not responding or being updated. Please try again in a few minutes.");
    } finally {
        loader.style.display = "none";
        checkBtn.disabled = false;
        if (bulkBtn) bulkBtn.disabled = false;
        isLoading = false;

        resultsSection.style.display = "block";
        exportBtn.style.display = "inline-block";
    }
}

function getStatusLevel(record) {
    if (!record) return "error";
    if (record.level) return record.level;
    return record.status ? "success" : "error";
}

function createRecordTypeLabel(type) {
    const wrapper = document.createElement("span");
    wrapper.className = "record-type tooltip";

    const documentationLink = recordDocumentationLinks[type];
    let label;
    if (documentationLink) {
        label = document.createElement("a");
        label.href = documentationLink;
        label.target = "_blank";
        label.rel = "noopener noreferrer";
        label.className = "record-type-link";
    } else {
        label = document.createElement("span");
    }
    label.textContent = type;
    wrapper.appendChild(label);

    const description = recordDescriptions[type];
    if (description) {
        const tooltip = document.createElement("span");
        tooltip.className = "tooltip-text record-tooltip-text";
        const descriptionText = document.createElement("span");
        descriptionText.textContent = description;
        tooltip.appendChild(descriptionText);

        if (documentationLink) {
            const link = document.createElement("a");
            link.href = documentationLink;
            link.target = "_blank";
            link.rel = "noopener noreferrer";
            link.textContent = "📖 Read more";
            tooltip.appendChild(link);
        }

        wrapper.appendChild(tooltip);
    }

    return wrapper;
}

function createStatusIcon(record) {
    const level = getStatusLevel(record);
    const span = document.createElement("span");
    span.className = `status-icon status-${level} tooltip`;

    const icons = {
        success: {
            label: "Passed",
            svg: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M16.7 5.3a1 1 0 0 1 0 1.4l-7.6 7.6a1 1 0 0 1-1.4 0L3.3 9.9a1 1 0 1 1 1.4-1.4l3.7 3.7 6.9-6.9a1 1 0 0 1 1.4 0Z"/></svg>'
        },
        warning: {
            label: "Warning",
            svg: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M9.1 3.2a1 1 0 0 1 1.8 0l7 12.5A1 1 0 0 1 17 17H3a1 1 0 0 1-.9-1.5l7-12.3ZM10 7a1 1 0 0 0-1 1v3a1 1 0 1 0 2 0V8a1 1 0 0 0-1-1Zm0 7.8a1.1 1.1 0 1 0 0-2.2 1.1 1.1 0 0 0 0 2.2Z"/></svg>'
        },
        error: {
            label: "Failed",
            svg: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M5.3 4a1 1 0 0 0-1.4 1.4L8.6 10l-4.7 4.6A1 1 0 1 0 5.3 16l4.6-4.7 4.7 4.7a1 1 0 0 0 1.4-1.4L11.3 10 16 5.4A1 1 0 0 0 14.6 4L9.9 8.6 5.3 4Z"/></svg>'
        }
    };

    const icon = icons[level] || icons.error;
    span.innerHTML = icon.svg;
    span.setAttribute("role", "img");
    span.setAttribute("aria-label", icon.label);
    span.title = icon.label;

    const tooltipText = getStatusTooltipText(record, icon.label);
    if (tooltipText) {
        const tooltip = document.createElement("span");
        tooltip.className = "tooltip-text status-tooltip-text";
        tooltip.textContent = tooltipText;
        span.appendChild(tooltip);
    }

    return span;
}

function formatValueForTitle(value) {
    if (Array.isArray(value)) return value.join("\n");
    return (value ?? "").toString();
}

function getStatusTooltipText(record, fallbackLabel) {
    if (!record) return "No data";
    if (record.type === "DANE") return record.status ? fallbackLabel : "The MX record does not support DANE.";
    if (record.advisories?.length) return record.advisories.join("\n");
    if (record.status === false) return formatValueForTitle(record.value);
    if (record.skipped) return formatValueForTitle(record.value);
    return fallbackLabel;
}

function createValueNode(value) {
    const text = String(value ?? "");
    if (/^https?:\/\//i.test(text)) {
        const link = document.createElement("a");
        link.href = text;
        link.target = "_blank";
        link.rel = "noopener";
        link.textContent = text;
        return link;
    }
    return document.createTextNode(text);
}

function appendRecordDetails(cell, record) {
    const value = record?.value;
    const values = Array.isArray(value) ? value : [value];
    const list = document.createElement("ul");

    values.forEach((val) => {
        const li = document.createElement("li");
        li.appendChild(createValueNode(val));
        list.appendChild(li);
    });

    cell.appendChild(list);
}

function formatWhoisLabel(key) {
    const labels = {
        domain_name: "Domain name",
        registrar: "Registrar",
        whois_server: "WHOIS server",
        creation_date: "Date of registration",
        updated_date: "Last updated",
        expiration_date: "Expiration date",
        name: "Contact name",
        organization: "Organization",
        address: "Address",
        city: "City",
        state: "State/Province",
        zipcode: "Postal code",
        country: "Country",
        emails: "Email",
        phone: "Phone",
        administrative_contact: "Administrative contact",
        status: "Domain status"
    };
    return labels[key] || key.replaceAll("_", " ");
}

function formatWhoisValue(value) {
    if (Array.isArray(value)) {
        return value.map(formatWhoisValue).join("; ");
    }
    if (value && typeof value === "object") {
        return Object.entries(value)
            .map(([key, val]) => `${formatWhoisLabel(key)}: ${formatWhoisValue(val)}`)
            .join(", ");
    }
    return String(value);
}

function appendValue(target, value) {
    target.appendChild(document.createTextNode(formatWhoisValue(value)));
}

function createWhoisList(whoisData) {
    const list = document.createElement("ul");
    const order = [
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
        "status"
    ];

    for (const key of order) {
        const value = whoisData[key];
        if (!value || (Array.isArray(value) && value.length === 0)) continue;

        const item = document.createElement("li");
        const label = document.createElement("strong");
        label.textContent = `${formatWhoisLabel(key)}: `;
        item.appendChild(label);
        appendValue(item, value);
        list.appendChild(item);
    }

    if (!list.children.length) {
        const item = document.createElement("li");
        item.textContent = "No public WHOIS details found.";
        list.appendChild(item);
    }

    return list;
}

async function runBulkLookup() {
    if (isLoading) return;

    const bulkTextarea = document.getElementById("bulkTextarea");
    const bulkRunBtn = document.getElementById("bulkRunBtn");
    const bulkBtn = document.getElementById("bulkBtn");
    const checkBtn = document.getElementById("checkBtn");
    const exportBtn = document.getElementById("exportBtn");

    const raw = (bulkTextarea?.value || "").split(/\r?\n/);
    const domains = raw
        .map(normalizeDomain)
        .filter((d) => d.length > 0);

    // de-duplicate while preserving order
    const seen = new Set();
    const uniqueDomains = [];
    for (const d of domains) {
        if (!seen.has(d)) {
            seen.add(d);
            uniqueDomains.push(d);
        }
    }

    const invalid = uniqueDomains.filter((d) => !isValidDomain(d));
    if (uniqueDomains.length === 0) {
        alert("Paste at least 1 domain (one per line).");
        return;
    }
    if (invalid.length > 0) {
        alert("Invalid domains found:\n\n" + invalid.slice(0, 25).join("\n"));
        return;
    }

    closeBulkModal();

    isLoading = true;
    currentMode = "bulk";
    document.querySelector(".container")?.classList.add("bulk-mode");

    checkBtn.disabled = true;
    if (bulkBtn) bulkBtn.disabled = true;
    if (bulkRunBtn) bulkRunBtn.disabled = true;

    const loader = document.getElementById("loader");
    const resultsSection = document.getElementById("resultsSection");
    const bulkResultsSection = document.getElementById("bulkResultsSection");
    const bulkProgressText = document.getElementById("bulkProgressText");
    const bulkTbody = document.querySelector("#bulkTable tbody");

    // Hide single results, show loader
    resultsSection.style.display = "none";
    exportBtn.style.display = "none";
    if (bulkResultsSection) bulkResultsSection.style.display = "none";
    loader.style.display = "flex";

    // Reset bulk table
    if (bulkTbody) bulkTbody.innerHTML = "";
    if (bulkProgressText) {
        bulkProgressText.style.display = "block";
        bulkProgressText.textContent = `0/${uniqueDomains.length} processed...`;
    }

    const recordCols = recordOrder;

    try {
        for (let i = 0; i < uniqueDomains.length; i++) {
            const domain = uniqueDomains[i];

            let data = null;
            try {
                const response = await fetch(`/api/lookup?domain=${encodeURIComponent(domain)}`);
                data = await response.json();
            } catch (e) {
                data = null;
            }

            const row = document.createElement("tr");

            const domainCell = document.createElement("td");
            domainCell.textContent = domain;
            row.appendChild(domainCell);

            for (const col of recordCols) {
                const cell = document.createElement("td");
                if (data && data[col]) {
                    data[col].type = col;
                    cell.appendChild(createStatusIcon(data[col]));
                    const advisories = data[col].advisories?.length ? `\n\nAdvisories:\n${data[col].advisories.join("\n")}` : "";
                    cell.title = formatValueForTitle(data[col].value) + advisories;
                } else {
                    cell.appendChild(createStatusIcon({ status: false }));
                    cell.title = "No data";
                }
                row.appendChild(cell);
            }

            // Nameservers column (API returns an array)
            const nsCell = document.createElement("td");
            if (data && data.NS) {
                if (Array.isArray(data.NS)) {
                    nsCell.textContent = data.NS.join(", ");
                    nsCell.title = data.NS.join("\n");
                } else {
                    nsCell.textContent = String(data.NS);
                    nsCell.title = String(data.NS);
                }
            } else {
                nsCell.textContent = "";
            }
            row.appendChild(nsCell);

            if (bulkTbody) bulkTbody.appendChild(row);

            if (bulkProgressText) {
                bulkProgressText.textContent = `${i + 1}/${uniqueDomains.length} processed...`;
            }
        }
    } finally {
        loader.style.display = "none";
        isLoading = false;

        checkBtn.disabled = false;
        if (bulkBtn) bulkBtn.disabled = false;
        if (bulkRunBtn) bulkRunBtn.disabled = false;

        if (bulkProgressText) bulkProgressText.style.display = "none";
        if (bulkResultsSection) bulkResultsSection.style.display = "block";
        exportBtn.style.display = "inline-block";
    }
}

async function exportReport() {
    const exportBtn = document.getElementById("exportBtn");
    if (exportBtn.disabled) return;

    let table = null;
    let filename = "";
    let label = "";
    let count = 0;
    let templateFile = "export-template-single.html";

    if (currentMode === "bulk") {
        table = document.querySelector("#bulkTable");
        count = document.querySelectorAll("#bulkTable tbody tr").length;
        label = `Bulk export (${count} domains)`;
        filename = "bulk_dns_report.html";
        templateFile = "export-template-bulk.html";
    } else {
        table = document.querySelector("#resultTable");
        const domain = normalizeDomain(document.getElementById("domainInput").value);
        if (!isValidDomain(domain)) {
            alert("The input does not appear to be a valid domain. Please check your entry.");
            return;
        }
        label = domain;
        filename = domain + "_dns_report.html";
        templateFile = "export-template-single.html";
    }

    let tableHTML = "";
    if (table) {
        const clone = table.cloneNode(true);
        tableHTML = clone.outerHTML;
    }

    const template = await fetch(templateFile).then((r) => r.text());

    const filled = template
        .replaceAll("{{domain}}", label)
        .replaceAll("{{count}}", String(count))
        .replace("{{report_content}}", tableHTML);

    const blob = new Blob([filled], { type: "text/html;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", filename);
    link.style.display = "none";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}
