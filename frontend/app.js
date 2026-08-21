let isLoading = false;
let currentMode = "single"; // "single" | "bulk"
let lastCheckedDomain = "";
let lastBulkResults = [];
let lastDomainDetailsData = null;
const appUrl = "https://tools.justinverstijnen.nl/dnsmegatool";
const detailsModalAnimationMs = 420;

const recordDescriptions = {
    "MX": "Mail Exchange records tells the internet where the server of your domain is.",
    "SPF": "Sender Policy Framework lists which servers are trusted to send email for this domain.",
    "DKIM": "DomainKeys Identified Mail uses cryptographic signatures so receivers can verify email was authorized by the sender.",
    "DMARC": "Domain-based Message Authentication, Reporting and Conformance tells receivers what to do when SPF or DKIM checks fail.",
    "TLS-RPT": "SMTP TLS Reporting publishes where mail providers should send reports about encrypted mail delivery problems.",
    "MTA-STS": "Mail Transfer Agent Strict Transport Security tells mail servers to require encrypted SMTP delivery for this domain.",
    "DNSSEC": "Domain Name System Security Extensions add signed DNS data so resolvers can detect forged DNS answers.",
    "DANE": "DNS-based Authentication of Named Entities publishes TLSA records so SMTP TLS certificates can be validated through DNSSEC."
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

const recordOrder = ["MX", "SPF", "DKIM", "DMARC", "TLS-RPT", "DNSSEC", "DANE", "MTA-STS"];

document.addEventListener("DOMContentLoaded", function () {
    const domainInput = document.getElementById("domainInput");
    const checkBtn = document.getElementById("checkBtn");
    const bulkBtn = document.getElementById("bulkBtn");
    const exportBtn = document.getElementById("exportBtn");
    const exportControl = document.getElementById("exportControl");
    const detailsBtn = document.getElementById("detailsBtn");
    const detailsExportBtn = document.getElementById("detailsExportBtn");
    const detailsExportControl = document.getElementById("detailsExportControl");

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

    if (detailsBtn) {
        detailsBtn.addEventListener("click", function (event) {
            event.preventDefault();
            openDomainDetailsModal();
        });
    }

    const detailsClose = document.getElementById("detailsClose");
    if (detailsClose) detailsClose.addEventListener("click", closeDomainDetailsModal);

    const detailsModal = document.getElementById("detailsModal");
    if (detailsModal) {
        detailsModal.addEventListener("click", function (event) {
            if (event.target === detailsModal) closeDomainDetailsModal();
        });
    }

    document.addEventListener("keydown", function (event) {
        if (event.key === "Escape") {
            closeBulkModal();
            closeDomainDetailsModal();
            setExportMenuOpen(false);
            setDetailsExportMenuOpen(false);
        }
    });

    if (exportControl) {
        exportControl.addEventListener("click", function (event) {
            event.stopPropagation();
        });
    }

    if (exportBtn) {
        exportBtn.addEventListener("click", function (event) {
            event.preventDefault();
            setExportMenuOpen(!exportControl?.classList.contains("open"));
        });
    }

    document.querySelectorAll("[data-export-format]").forEach((item) => {
        item.addEventListener("click", function (event) {
            event.preventDefault();
            setExportMenuOpen(false);
            exportReport(item.dataset.exportFormat || "html");
        });
    });

    if (detailsExportControl) {
        detailsExportControl.addEventListener("click", function (event) {
            event.stopPropagation();
        });
    }

    if (detailsExportBtn) {
        detailsExportBtn.addEventListener("click", function (event) {
            event.preventDefault();
            if (detailsExportBtn.disabled) return;
            setDetailsExportMenuOpen(!detailsExportControl?.classList.contains("open"));
        });
    }

    document.querySelectorAll("[data-details-export-format]").forEach((item) => {
        item.addEventListener("click", function (event) {
            event.preventDefault();
            setDetailsExportMenuOpen(false);
            exportDomainDetails(item.dataset.detailsExportFormat || "html");
        });
    });

    document.addEventListener("click", function () {
        setExportMenuOpen(false);
        setDetailsExportMenuOpen(false);
    });
});

function setExportMenuVisible(isVisible) {
    const exportControl = document.getElementById("exportControl");
    if (!exportControl) return;
    exportControl.style.display = isVisible ? "inline-flex" : "none";
    if (!isVisible) setExportMenuOpen(false);
}

function setExportMenuOpen(isOpen) {
    const exportControl = document.getElementById("exportControl");
    const exportBtn = document.getElementById("exportBtn");
    if (!exportControl) return;

    exportControl.classList.toggle("open", Boolean(isOpen));
    if (exportBtn) exportBtn.setAttribute("aria-expanded", isOpen ? "true" : "false");
}

function setDetailsExportMenuOpen(isOpen) {
    const detailsExportControl = document.getElementById("detailsExportControl");
    const detailsExportBtn = document.getElementById("detailsExportBtn");
    if (!detailsExportControl) return;

    detailsExportControl.classList.toggle("open", Boolean(isOpen));
    if (detailsExportBtn) detailsExportBtn.setAttribute("aria-expanded", isOpen ? "true" : "false");
}

function setDetailsExportEnabled(isEnabled) {
    const detailsExportBtn = document.getElementById("detailsExportBtn");
    if (!detailsExportBtn) return;

    detailsExportBtn.disabled = !isEnabled;
    if (!isEnabled) setDetailsExportMenuOpen(false);
}

function openBulkModal() {
    const bulkModal = document.getElementById("bulkModal");
    const bulkTextarea = document.getElementById("bulkTextarea");
    if (!bulkModal || !bulkTextarea) return;

    bulkModal.classList.remove("modal-closing");
    bulkModal.style.display = "flex";
    requestAnimationFrame(() => bulkModal.classList.add("modal-open"));
    setTimeout(() => bulkTextarea.focus(), 0);
}

function closeBulkModal() {
    const bulkModal = document.getElementById("bulkModal");
    if (!bulkModal) return;
    if (bulkModal.style.display === "none") return;

    bulkModal.classList.remove("modal-open");
    bulkModal.classList.add("modal-closing");

    window.setTimeout(() => {
        if (!bulkModal.classList.contains("modal-open")) {
            bulkModal.style.display = "none";
            bulkModal.classList.remove("modal-closing");
        }
    }, detailsModalAnimationMs);
}

function getRegistrarName(data) {
    const registrar = data?.WHOIS?.registrar;
    if (!registrar || (Array.isArray(registrar) && registrar.length === 0)) return "";
    return formatWhoisValue(registrar);
}

function setBulkProgress(processed, total) {
    const bulkProgressText = document.getElementById("bulkProgressText");
    const bulkProgressBar = document.getElementById("bulkProgressBar");
    const bulkProgressFill = document.getElementById("bulkProgressFill");
    const percent = total > 0 ? Math.round((processed / total) * 100) : 0;

    if (bulkProgressText) {
        bulkProgressText.style.display = "block";
        bulkProgressText.textContent = `${processed}/${total} domains processed...`;
    }

    if (bulkProgressBar) {
        bulkProgressBar.style.display = "block";
        bulkProgressBar.setAttribute("aria-valuenow", String(percent));
        bulkProgressBar.setAttribute("aria-label", `${processed} of ${total} domains processed`);
    }

    if (bulkProgressFill) {
        bulkProgressFill.style.width = `${percent}%`;
    }
}

function hideBulkProgress() {
    const bulkProgressText = document.getElementById("bulkProgressText");
    const bulkProgressBar = document.getElementById("bulkProgressBar");
    const bulkProgressFill = document.getElementById("bulkProgressFill");

    if (bulkProgressText) bulkProgressText.style.display = "none";
    if (bulkProgressBar) bulkProgressBar.style.display = "none";
    if (bulkProgressFill) bulkProgressFill.style.width = "0%";
}

function isStandaloneLookupNotice(data) {
    return ["available", "dns_refused", "dns_error"].includes(data?.WHOIS?.lookup_status);
}

function createMicrosoftTenantBox(tenantData, domain) {
    if (!tenantData?.detected || !tenantData.tenant_id) return null;

    const box = document.createElement("div");
    box.className = "infobox tenant-infobox";

    const title = document.createElement("h3");
    title.textContent = "Microsoft 365 tenant detected";
    box.appendChild(title);

    const tenantRow = document.createElement("div");
    tenantRow.className = "tenant-id-row";

    const label = document.createElement("strong");
    label.textContent = "Tenant ID: ";
    tenantRow.appendChild(label);

    const tenantId = document.createElement("code");
    tenantId.textContent = tenantData.tenant_id;
    tenantRow.appendChild(tenantId);

    box.appendChild(tenantRow);

    const detectedDomain = tenantData.domain || domain;
    if (detectedDomain) {
        const domainLine = document.createElement("div");
        domainLine.className = "tenant-domain-line";
        domainLine.textContent = `Detected for ${detectedDomain}`;
        box.appendChild(domainLine);
    }

    return box;
}

async function openDomainDetailsModal() {
    const domain = lastCheckedDomain || normalizeDomain(document.getElementById("domainInput").value);
    if (!isValidDomain(domain)) {
        alert("The input does not appear to be a valid domain. Please check your entry.");
        return;
    }

    const detailsModal = document.getElementById("detailsModal");
    const detailsTitle = document.getElementById("detailsTitle");
    const detailsSubtitle = document.getElementById("detailsSubtitle");
    const detailsBody = document.getElementById("detailsBody");
    if (!detailsModal || !detailsTitle || !detailsSubtitle || !detailsBody) return;

    detailsTitle.textContent = "Domain details";
    detailsSubtitle.textContent = domain;
    lastDomainDetailsData = null;
    setDetailsExportEnabled(false);
    detailsBody.innerHTML = "";
    detailsBody.appendChild(createDetailsLoadingState());
    detailsModal.classList.remove("modal-closing");
    detailsModal.style.display = "flex";
    requestAnimationFrame(() => detailsModal.classList.add("modal-open"));

    try {
        const response = await fetch(`/api/domain-details?domain=${encodeURIComponent(domain)}`);
        if (!response.ok) throw new Error(`Details lookup failed with status ${response.status}`);
        const data = await response.json();
        renderDomainDetails(data);
    } catch (error) {
        console.error(error);
        detailsBody.innerHTML = "";
        const errorBox = document.createElement("div");
        errorBox.className = "domain-details-empty";
        errorBox.textContent = "Domain details could not be loaded. Please try again in a few moments.";
        detailsBody.appendChild(errorBox);
    }
}

function closeDomainDetailsModal() {
    const detailsModal = document.getElementById("detailsModal");
    if (!detailsModal) return;
    if (detailsModal.style.display === "none") return;

    setDetailsExportMenuOpen(false);
    detailsModal.classList.remove("modal-open");
    detailsModal.classList.add("modal-closing");

    window.setTimeout(() => {
        if (!detailsModal.classList.contains("modal-open")) {
            detailsModal.style.display = "none";
            detailsModal.classList.remove("modal-closing");
        }
    }, detailsModalAnimationMs);
}

function createDetailsLoadingState() {
    const wrapper = document.createElement("div");
    wrapper.className = "domain-details-loading";

    const spinner = document.createElement("div");
    spinner.className = "details-spinner";

    const text = document.createElement("span");
    text.textContent = "Loading DNS records...";

    wrapper.appendChild(spinner);
    wrapper.appendChild(text);
    return wrapper;
}

function renderDomainDetails(data) {
    const detailsBody = document.getElementById("detailsBody");
    if (!detailsBody) return;

    lastDomainDetailsData = data || null;
    setDetailsExportEnabled(Boolean(data?.sections?.length));
    detailsBody.innerHTML = "";

    if (!data?.sections?.length) {
        const empty = document.createElement("div");
        empty.className = "domain-details-empty";
        empty.textContent = "No DNS details were returned for this domain.";
        detailsBody.appendChild(empty);
        return;
    }

    data.sections.forEach((section) => {
        detailsBody.appendChild(createDomainDetailsSection(section, data.domain));
    });
}

function formatRecordSectionTitle(type) {
    if (type === "SOA") return `${type} record`;
    return `${type} records`;
}

function formatDomainDetailName(name, domainName) {
    const domain = normalizeDomain(domainName || lastCheckedDomain);
    const cleanName = String(name || "").trim().replace(/\.$/, "");

    if (!cleanName || cleanName === "@") return "@";
    if (!domain) return cleanName;

    const lowerName = cleanName.toLowerCase();
    const lowerDomain = domain.toLowerCase();
    if (lowerName === lowerDomain) return "@";
    if (lowerName.endsWith(`.${lowerDomain}`)) {
        return cleanName.slice(0, -(domain.length + 1)) || "@";
    }

    return cleanName;
}

function createDomainDetailsSection(section, domainName) {
    const wrapper = document.createElement("section");
    wrapper.className = "domain-details-section";

    const heading = document.createElement("h3");
    heading.textContent = formatRecordSectionTitle(section.type);
    wrapper.appendChild(heading);

    if (section.description) {
        const description = document.createElement("p");
        description.className = "domain-details-description";
        description.textContent = section.description;
        wrapper.appendChild(description);
    }

    if (!section.records?.length) {
        const empty = document.createElement("p");
        empty.className = "domain-details-empty";
        empty.textContent = section.message || `No ${section.type} records found.`;
        wrapper.appendChild(empty);
        return wrapper;
    }

    const table = document.createElement("table");
    table.className = "domain-details-table";

    const thead = document.createElement("thead");
    const headRow = document.createElement("tr");
    const headers = ["Name", "Record value"];

    headers.forEach((label) => {
        const th = document.createElement("th");
        th.textContent = label;
        headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = document.createElement("tbody");
    section.records.forEach((record) => {
        const row = document.createElement("tr");

        const nameCell = document.createElement("td");
        nameCell.appendChild(createValueNode(formatDomainDetailName(record.name || section.name, domainName)));
        row.appendChild(nameCell);

        const valueCell = document.createElement("td");
        valueCell.appendChild(createValueNode(record.value));
        row.appendChild(valueCell);

        tbody.appendChild(row);
    });
    table.appendChild(tbody);

    wrapper.appendChild(table);
    return wrapper;
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
    lastBulkResults = [];

    document.querySelector(".container")?.classList.remove("bulk-mode");

    const checkBtn = document.getElementById("checkBtn");
    const bulkBtn = document.getElementById("bulkBtn");
    const exportBtn = document.getElementById("exportBtn");
    const detailsBtn = document.getElementById("detailsBtn");

    checkBtn.disabled = true;
    if (bulkBtn) bulkBtn.disabled = true;
    if (detailsBtn) detailsBtn.style.display = "none";
    lastCheckedDomain = "";

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
    const resultTableWrapper = document.querySelector("#resultTable")?.closest(".table-wrapper");
    const extraInfo = document.getElementById("extraInfo");
    let showDetailsButton = false;

    // Reset views
    if (bulkResultsSection) bulkResultsSection.style.display = "none";
    resultsSection.style.display = "none";
    setExportMenuVisible(false);
    loader.style.display = "flex";

    // Clear existing content
    tbody.innerHTML = "";
    extraInfo.innerHTML = "";
    if (resultTableWrapper) resultTableWrapper.style.display = "";

    try {
        const response = await fetch(`/api/lookup?domain=${encodeURIComponent(domain)}`);
        if (!response.ok) throw new Error(`Lookup failed with status ${response.status}`);
        const data = await response.json();
        lastCheckedDomain = domain;
        const standaloneLookupNotice = isStandaloneLookupNotice(data);
        showDetailsButton = Boolean(lastCheckedDomain && !standaloneLookupNotice);
        if (resultTableWrapper) resultTableWrapper.style.display = standaloneLookupNotice ? "none" : "";

        if (!standaloneLookupNotice) {
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
        }

        // Extra info: Microsoft 365 tenant
        if (!standaloneLookupNotice) {
            const tenantBox = createMicrosoftTenantBox(data.TENANT, domain);
            if (tenantBox) extraInfo.appendChild(tenantBox);
        }

        // Extra info: Nameservers (API returns an array)
        if (!standaloneLookupNotice && data.NS) {
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
            whoisTitle.textContent = data.WHOIS?.lookup_status?.startsWith("dns_")
                ? `DNS lookup for ${domain}:`
                : `WHOIS Information for ${domain}:`;
            whoisBox.appendChild(whoisTitle);

            const whoisMessage = createWhoisMessage(data.WHOIS);
            if (whoisMessage) whoisBox.appendChild(whoisMessage);
            whoisBox.appendChild(createWhoisList(data.WHOIS));

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
        setExportMenuVisible(true);
        if (detailsBtn && showDetailsButton) detailsBtn.style.display = "inline-flex";
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
        const tooltip = documentationLink ? document.createElement("a") : document.createElement("span");
        tooltip.className = "tooltip-text record-tooltip-text";
        if (documentationLink) {
            tooltip.href = documentationLink;
            tooltip.target = "_blank";
            tooltip.rel = "noopener noreferrer";
            tooltip.setAttribute("aria-label", `Read more about ${type}`);
        }

        const descriptionText = document.createElement("span");
        descriptionText.textContent = description;
        tooltip.appendChild(descriptionText);

        if (documentationLink) {
            const readMore = document.createElement("span");
            readMore.className = "tooltip-read-more";
            readMore.textContent = "Read more";
            tooltip.appendChild(readMore);
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
    if (Array.isArray(value)) return value.map(formatValueForTitle).join("\n");
    if (value && typeof value === "object") {
        if (value.kind === "dkim") {
            const lines = [];
            (value.sections || []).forEach((section) => {
                lines.push(section.selector);
                (section.values || []).forEach((line) => lines.push(String(line ?? "")));
                (section.details || []).forEach((line) => lines.push(String(line ?? "")));
            });
            if (value.additional_sections?.length) {
                value.additional_sections.forEach((section) => {
                    lines.push(section.selector);
                    (section.values || []).forEach((line) => lines.push(String(line ?? "")));
                    (section.details || []).forEach((line) => lines.push(String(line ?? "")));
                });
            }
            if (value.action?.command) lines.push(value.action.command);
            return lines.join("\n");
        }
        const lines = [];
        if (value.text !== undefined && value.text !== null) lines.push(String(value.text));
        if (Array.isArray(value.details)) {
            value.details.forEach((detail) => lines.push(String(detail ?? "")));
        }
        return lines.join("\n");
    }
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
        link.rel = "noopener noreferrer";
        link.textContent = text;
        return link;
    }
    return document.createTextNode(text);
}

function normalizeRecordValueLines(value) {
    if (value && typeof value === "object") {
        if (value.kind === "dkim") {
            const lines = [];
            (value.sections || []).forEach((section) => {
                lines.push(section.selector);
                (section.values || []).forEach((line) => lines.push(String(line ?? "")));
                (section.details || []).forEach((line) => lines.push(String(line ?? "")));
            });
            if (value.additional_sections?.length) {
                value.additional_sections.forEach((section) => {
                    lines.push(section.selector);
                    (section.values || []).forEach((line) => lines.push(String(line ?? "")));
                    (section.details || []).forEach((line) => lines.push(String(line ?? "")));
                });
            }
            if (value.action?.command) lines.push(value.action.command);
            return lines;
        }
        const lines = [];
        if (value.text !== undefined && value.text !== null) lines.push(String(value.text));
        if (Array.isArray(value.details)) {
            value.details.forEach((detail) => lines.push(String(detail ?? "")));
        }
        return lines.length ? lines : [JSON.stringify(value)];
    }

    return String(value ?? "")
        .split(/\r?\n/)
        .map((line) => line.trimEnd());
}

function getRecordStatusLabel(record) {
    const level = getStatusLevel(record);
    if (level === "success") return "Passed";
    if (level === "warning") return "Warning";
    return "Failed";
}

function serializeRecordForJsonExport(record) {
    if (!record) {
        return {
            passed: false,
            status: "Failed",
            level: "error",
            values: [],
            advisories: ["No data"]
        };
    }

    const values = Array.isArray(record.value)
        ? record.value.flatMap((value) => normalizeRecordValueLines(value))
        : normalizeRecordValueLines(record.value);

    return {
        passed: record.status === true,
        status: getRecordStatusLabel(record),
        level: getStatusLevel(record),
        values,
        raw_value: record.value ?? null,
        advisories: Array.isArray(record.advisories) ? record.advisories : []
    };
}

function serializeBulkLookupForJsonExport(domain, data) {
    const records = {};

    recordOrder.forEach((type) => {
        const record = data?.[type] ? { ...data[type], type } : null;
        records[type] = serializeRecordForJsonExport(record);
    });

    const dnsServers = Array.isArray(data?.NS)
        ? data.NS
        : data?.NS
            ? [String(data.NS)]
            : [];

    records["DNS servers"] = {
        passed: dnsServers.length > 0,
        status: dnsServers.length > 0 ? "Passed" : "Failed",
        level: dnsServers.length > 0 ? "success" : "error",
        values: dnsServers,
        raw_value: data?.NS ?? null,
        advisories: dnsServers.length > 0 ? [] : ["No DNS servers found"]
    };

    return { domain, registrar: getRegistrarName(data), records };
}

function appendRecordValueLines(listItem, value) {
    const lines = normalizeRecordValueLines(value);

    lines.forEach((line, index) => {
        const lineElement = document.createElement("div");
        if (index > 0) lineElement.className = "record-value-detail";
        lineElement.appendChild(createValueNode(line));
        listItem.appendChild(lineElement);
    });
}

function appendDkimSection(list, section, extraClass = "") {
    const values = Array.isArray(section.values) && section.values.length
        ? section.values
        : [];

    if (!values.length) {
        const statusItem = document.createElement("li");
        statusItem.className = `dkim-section ${extraClass}`.trim();

        const selectorLabel = document.createElement("strong");
        selectorLabel.textContent = `${section.selector}: `;
        statusItem.appendChild(selectorLabel);

        const statusText = document.createElement("span");
        statusText.className = "dkim-key-value";
        statusText.appendChild(createValueNode((section.details || [])[0] || "DKIM key not found"));
        statusItem.appendChild(statusText);

        list.appendChild(statusItem);
        return;
    }

    values.forEach((value, valueIndex) => {
        const valueItem = document.createElement("li");
        valueItem.className = `dkim-section ${extraClass}`.trim();

        const selectorLabel = document.createElement("strong");
        selectorLabel.textContent = `${section.selector}: `;
        valueItem.appendChild(selectorLabel);

        const keyValue = document.createElement("span");
        keyValue.className = "dkim-key-value";
        keyValue.appendChild(createValueNode(value));
        valueItem.appendChild(keyValue);

        list.appendChild(valueItem);

        if (valueIndex === 0) {
            (section.details || []).forEach((detail) => {
                const detailItem = document.createElement("li");
                detailItem.className = "record-value-detail dkim-detail-item";
                detailItem.appendChild(createValueNode(detail));
                list.appendChild(detailItem);
            });
        }
    });
}

function appendDkimAction(list, action) {
    if (!action?.command) return;

    const li = document.createElement("li");
    li.className = "dkim-action";

    const intro = document.createElement("div");
    intro.className = "record-value-detail";
    intro.textContent = action.message || "Rotate the Microsoft 365 DKIM signing configuration:";
    li.appendChild(intro);

    const command = document.createElement("code");
    command.textContent = action.command;
    li.appendChild(command);

    if (action.url) {
        const link = document.createElement("a");
        link.href = action.url;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.textContent = action.url;
        li.appendChild(link);
    }

    list.appendChild(li);
}

function appendDkimDetails(cell, record) {
    const value = record?.value || {};
    const list = document.createElement("ul");
    list.className = "dkim-list";

    (value.sections || []).forEach((section, index) => {
        appendDkimSection(list, section, index > 0 ? "dkim-separated" : "");
    });

    if (value.additional_sections?.length) {
        value.additional_sections.forEach((section, index) => {
            appendDkimSection(list, section, index === 0 ? "dkim-separated dkim-extra-record" : "dkim-extra-record");
        });
    }

    appendDkimAction(list, value.action);
    cell.appendChild(list);
}

function appendRecordDetails(cell, record) {
    if (record?.type === "DKIM" && record?.value?.kind === "dkim") {
        appendDkimDetails(cell, record);
        return;
    }

    const value = record?.value;
    const values = Array.isArray(value) ? value : [value];
    const list = document.createElement("ul");

    values.forEach((val) => {
        const li = document.createElement("li");
        appendRecordValueLines(li, val);
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

function createWhoisMessage(whoisData) {
    const message = whoisData?.lookup_message || whoisData?.error;
    if (!message) return null;

    const text = document.createElement("p");
    text.className = "whois-message";
    if (whoisData?.lookup_status === "available") {
        text.appendChild(document.createTextNode("This domain is "));
        const strong = document.createElement("strong");
        strong.textContent = "free";
        text.appendChild(strong);
        text.appendChild(document.createTextNode(" and available for registration."));
    } else if (whoisData?.lookup_status === "dns_refused") {
        text.appendChild(document.createTextNode("The DNS servers "));
        const strong = document.createElement("strong");
        strong.textContent = "refused";
        text.appendChild(strong);
        text.appendChild(document.createTextNode(" the lookup request for this domain."));
        if (whoisData.technical_message) {
            text.appendChild(document.createElement("br"));
            text.appendChild(document.createTextNode(whoisData.technical_message));
        }
    } else if (whoisData?.lookup_status === "dns_error") {
        text.appendChild(document.createTextNode("The DNS records could not be checked for this domain."));
        if (whoisData.technical_message && whoisData.technical_message !== message) {
            text.appendChild(document.createElement("br"));
            text.appendChild(document.createTextNode(whoisData.technical_message));
        } else {
            text.appendChild(document.createElement("br"));
            text.appendChild(document.createTextNode(message));
        }
    } else {
        text.textContent = message;
    }
    return text;
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
        item.textContent = whoisData?.lookup_message || whoisData?.error || "No public WHOIS details found.";
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
    const detailsBtn = document.getElementById("detailsBtn");

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
    closeDomainDetailsModal();

    isLoading = true;
    currentMode = "bulk";
    lastCheckedDomain = "";
    lastBulkResults = [];
    document.querySelector(".container")?.classList.add("bulk-mode");

    checkBtn.disabled = true;
    if (bulkBtn) bulkBtn.disabled = true;
    if (bulkRunBtn) bulkRunBtn.disabled = true;
    if (detailsBtn) detailsBtn.style.display = "none";

    const loader = document.getElementById("loader");
    const resultsSection = document.getElementById("resultsSection");
    const bulkResultsSection = document.getElementById("bulkResultsSection");
    const bulkTbody = document.querySelector("#bulkTable tbody");

    // Hide single results and show the bulk table immediately so rows can stream in.
    resultsSection.style.display = "none";
    setExportMenuVisible(false);
    if (bulkResultsSection) bulkResultsSection.style.display = "block";
    loader.style.display = "none";

    // Reset bulk table
    if (bulkTbody) bulkTbody.innerHTML = "";
    setBulkProgress(0, uniqueDomains.length);

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

            const bulkExportRow = serializeBulkLookupForJsonExport(domain, data);
            if (!data) {
                bulkExportRow.error = "Lookup failed";
            }
            lastBulkResults.push(bulkExportRow);

            const row = document.createElement("tr");
            row.className = "bulk-row-enter";

            const domainCell = document.createElement("td");
            const domainName = document.createElement("div");
            domainName.className = "bulk-domain-name";
            domainName.textContent = domain;
            domainCell.appendChild(domainName);

            const registrarName = getRegistrarName(data);
            if (registrarName) {
                const registrarLabel = document.createElement("code");
                registrarLabel.className = "bulk-registrar-label";
                registrarLabel.textContent = registrarName;
                registrarLabel.title = `Registrar: ${registrarName}`;
                domainCell.appendChild(registrarLabel);
            }
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

            setBulkProgress(i + 1, uniqueDomains.length);
        }
    } finally {
        loader.style.display = "none";
        isLoading = false;

        checkBtn.disabled = false;
        if (bulkBtn) bulkBtn.disabled = false;
        if (bulkRunBtn) bulkRunBtn.disabled = false;

        hideBulkProgress();
        if (bulkResultsSection) bulkResultsSection.style.display = "block";
        setExportMenuVisible(true);
    }
}

function getCleanElementText(element) {
    const clone = element.cloneNode(true);
    clone.querySelectorAll(".tooltip-text").forEach((tooltip) => tooltip.remove());
    return clone.textContent.replace(/\s+/g, " ").trim();
}

function getTableExportData(table) {
    if (!table) return { headers: [], rows: [] };

    const headers = Array.from(table.querySelectorAll("thead th")).map(getCleanElementText);
    const rows = Array.from(table.querySelectorAll("tbody tr")).map((row) => {
        return Array.from(row.children).map((cell) => {
            const statusIcon = cell.querySelector(".status-icon");
            if (statusIcon?.getAttribute("aria-label")) return statusIcon.getAttribute("aria-label");
            return getCleanElementText(cell);
        });
    });

    return { headers, rows };
}

function getCurrentExportContext() {
    let table = null;
    let filenameBase = "";
    let label = "";
    let count = 0;
    let templateFile = "export-template-single.html";

    if (currentMode === "bulk") {
        table = document.querySelector("#bulkTable");
        count = document.querySelectorAll("#bulkTable tbody tr").length;
        label = `Bulk export (${count} domains)`;
        filenameBase = "bulk_dns_report";
        templateFile = "export-template-bulk.html";
    } else {
        table = document.querySelector("#resultTable");
        const domain = normalizeDomain(document.getElementById("domainInput").value);
        if (!isValidDomain(domain)) {
            alert("The input does not appear to be a valid domain. Please check your entry.");
            return null;
        }
        label = domain;
        count = 1;
        filenameBase = `${domain}_dns_report`;
        templateFile = "export-template-single.html";
    }

    return { table, filenameBase, label, count, templateFile };
}

async function buildExportHtml(context) {
    let tableHTML = "";
    if (context.table) {
        const clone = context.table.cloneNode(true);
        tableHTML = clone.outerHTML;
    }

    const template = await fetch(context.templateFile).then((r) => r.text());

    return template
        .replaceAll("{{domain}}", context.label)
        .replaceAll("{{count}}", String(context.count))
        .replaceAll("{{app_url}}", appUrl)
        .replace("{{report_content}}", tableHTML);
}

function downloadBlob(content, filename, type) {
    const blob = new Blob([content], { type });
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

async function printReportAsPdf(html) {
    const printWindow = window.open("", "_blank");
    if (!printWindow) {
        alert("The PDF export could not be opened. Please allow pop-ups for this site and try again.");
        return;
    }

    printWindow.document.open();
    printWindow.document.write(html);
    printWindow.document.close();
    printWindow.focus();
    printWindow.setTimeout(() => printWindow.print(), 500);
}

function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function serializeDomainDetailsForExport(data) {
    const domain = data?.domain || lastCheckedDomain || normalizeDomain(document.getElementById("domainInput")?.value);

    return {
        generated_at: new Date().toISOString(),
        source: appUrl,
        mode: "domain-details",
        domain,
        sections: (data?.sections || []).map((section) => ({
            type: section.type,
            description: section.description || "",
            message: section.message || null,
            records: (section.records || []).map((record) => ({
                name: formatDomainDetailName(record.name || section.name, domain),
                fqdn: String(record.name || section.name || ""),
                value: String(record.value ?? ""),
                ttl: record.ttl ?? section.ttl ?? null,
                ttl_display: record.ttl_display || section.ttl_display || null,
                fields: record.fields || {},
            })),
        })),
    };
}

function buildDomainDetailsExportHtml(payload) {
    const sectionsHtml = payload.sections.map((section) => {
        const recordsHtml = section.records.length
            ? `<table>
                <thead><tr><th>Name</th><th>Record value</th></tr></thead>
                <tbody>
                    ${section.records.map((record) => `
                        <tr>
                            <td>${escapeHtml(record.name)}</td>
                            <td>${escapeHtml(record.value)}</td>
                        </tr>
                    `).join("")}
                </tbody>
            </table>`
            : `<p class="empty">${escapeHtml(section.message || `No ${section.type} records found.`)}</p>`;

        return `
            <section>
                <h2>${escapeHtml(formatRecordSectionTitle(section.type))}</h2>
                ${section.description ? `<p class="description">${escapeHtml(section.description)}</p>` : ""}
                ${recordsHtml}
            </section>
        `;
    }).join("");

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DNS MEGAtool domain details - ${escapeHtml(payload.domain)}</title>
  <style>
    body{font-family:Segoe UI,Arial,sans-serif;margin:24px;background:#f6f6f6;color:#111827}
    .wrap{max-width:1100px;margin:0 auto;background:#fff;padding:24px;border-radius:10px;box-shadow:0 0 15px rgba(0,0,0,.08)}
    .brand-logo{width:54px;height:54px;margin-bottom:10px}
    h1{margin:0 0 8px;text-align:center}
    .brand{text-align:center}
    .meta{color:#666;margin-bottom:22px;text-align:center}
    section{padding:18px 0;border-bottom:1px solid #e5e7eb}
    section:last-child{border-bottom:none}
    h2{margin:0 0 6px;font-size:21px}
    .description{margin:0 0 12px;color:#4b5563;font-size:14px}
    .empty{margin:0;color:#6b7280;font-size:14px}
    table{width:100%;border-collapse:collapse;table-layout:auto}
    th,td{border:1px solid #ddd;padding:10px;text-align:left;vertical-align:top;overflow-wrap:anywhere;word-break:break-word}
    th{background:#f2f2f2;font-size:13px}
    th:first-child,td:first-child{width:180px}
    .footer{color:#999;font-size:9px;margin-top:18px;text-align:center}
    .footer a{color:#999;text-decoration:none}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="brand">
      <a href="https://justinverstijnen.nl" target="_blank" rel="noopener">
        <img class="brand-logo" src="https://sajvwebsiteblobstorage.blob.core.windows.net/blog/tools-2375/logo.svg" alt="Justin Verstijnen logo">
      </a>
    </div>
    <h1>DNS MEGAtool domain details</h1>
    <div class="meta"><strong>Domain:</strong> ${escapeHtml(payload.domain)}</div>
    ${sectionsHtml}
    <div class="footer">
      <a href="${escapeHtml(appUrl)}" target="_blank" rel="noopener">Report generated with the Justin Verstijnen DNS MEGAtool.</a>
    </div>
  </div>
</body>
</html>`;
}

async function exportDomainDetails(format = "html") {
    const detailsExportBtn = document.getElementById("detailsExportBtn");
    if (!lastDomainDetailsData || detailsExportBtn?.disabled) return;

    const payload = serializeDomainDetailsForExport(lastDomainDetailsData);
    const filenameBase = `${payload.domain}_domain_details`;

    if (detailsExportBtn) detailsExportBtn.disabled = true;
    try {
        if (format === "json") {
            downloadBlob(JSON.stringify(payload, null, 2), `${filenameBase}.json`, "application/json;charset=utf-8;");
            return;
        }

        downloadBlob(buildDomainDetailsExportHtml(payload), `${filenameBase}.html`, "text/html;charset=utf-8;");
    } finally {
        if (detailsExportBtn) detailsExportBtn.disabled = false;
    }
}

async function exportReport(format = "html") {
    const exportBtn = document.getElementById("exportBtn");
    if (exportBtn.disabled) return;

    const context = getCurrentExportContext();
    if (!context) return;

    exportBtn.disabled = true;
    try {
        if (format === "json") {
            if (currentMode === "bulk") {
                downloadBlob(JSON.stringify({ domains: lastBulkResults }, null, 2), `${context.filenameBase}.json`, "application/json;charset=utf-8;");
                return;
            }

            const payload = {
                generated_at: new Date().toISOString(),
                source: appUrl,
                mode: currentMode,
                label: context.label,
                count: context.count,
                table: getTableExportData(context.table)
            };

            downloadBlob(JSON.stringify(payload, null, 2), `${context.filenameBase}.json`, "application/json;charset=utf-8;");
            return;
        }

        const html = await buildExportHtml(context);
        if (format === "pdf") {
            await printReportAsPdf(html);
            return;
        }

        downloadBlob(html, `${context.filenameBase}.html`, "text/html;charset=utf-8;");
    } finally {
        exportBtn.disabled = false;
    }
}
