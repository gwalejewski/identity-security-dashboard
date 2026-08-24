/**
 * GUARDRAIL: IDENTITY MFA SECURITY AUDIT FRONTEND CONTROLLER
 * Fetches compliance reports from the Cloudflare Worker backend and updates the UI widgets.
 */

// ==========================================================================
// APP STATE
// ==========================================================================
let currentReport = null;
let currentFilter = 'all';
let selectedRemediationId = null;

// Map of configured remediation guides
const REMEDIATION_STEPS = {
    "entra-ca-1": {
        title: "Enable MFA Policy for Admin Roles",
        platform: "Microsoft Entra ID",
        desc: "The critical Conditional Access policy 'Require MFA for High-Privilege Roles' is disabled. High-privilege directories are vulnerable to brute-force and credential stuffing.",
        steps: [
            "Navigate to the Microsoft Entra admin center (https://entra.microsoft.com).",
            "Go to Protection > Conditional Access > Policies.",
            "Select 'Require MFA for High-Privilege Roles'.",
            "Under 'Enable policy', switch the toggle from 'Off' or 'Report-only' to 'On'.",
            "Ensure that you do not accidentally lock yourself out. Exclude your current admin account temporarily if you have not registered MFA yet, verify access, and then remove the exclusion."
        ],
        codeLang: "PowerShell (Microsoft Graph CLI)",
        code: `# Enable the CA Policy\nUpdate-MgBetaIdentityConditionalAccessPolicy \\\n    -ConditionalAccessPolicyId "ca-policy-uuid-here" \\\n    -State "enabled"`
    },
    "entra-ca-2": {
        title: "Review Guest MFA Exclusion Groups",
        platform: "Microsoft Entra ID",
        desc: "Guest policy contains broad exclusions. Accounts in 'External Contractors Bypass' are allowed single-factor authentication.",
        steps: [
            "Identify all users currently assigned to the group 'External Contractors Bypass'.",
            "Remove active users from this group who should be prompted for MFA.",
            "For contractors that cannot configure standard phone-based MFA, enforce Cross-Tenant Access Settings to trust MFA configurations from their home directory, or require FIDO2 keys."
        ],
        codeLang: "PowerShell (Graph CLI)",
        code: `# Retrieve members of the exclusion group to audit\nGet-MgBetaGroupMember -GroupId "exclusion-group-uuid-here" | \\\n    Select-Object Id, UPN, DisplayName`
    },
    "entra-ca-4": {
        title: "Enforce Standard User base MFA Policy",
        platform: "Microsoft Entra ID",
        desc: "CA Policy for standard users is set to 'Report-only'. Report-only logs the authentication result but does not prompt for MFA challenges.",
        steps: [
            "Go to Protection > Conditional Access > Policies.",
            "Select 'MFA for Standard User Base'.",
            "Review sign-in logs to evaluate user impact (ensure most users have registered factors).",
            "Change the state of the policy to 'On'."
        ],
        codeLang: "PowerShell",
        code: `# Enforce Report-Only policy to Enabled\nUpdate-MgBetaIdentityConditionalAccessPolicy \\\n    -ConditionalAccessPolicyId "standard-policy-uuid" \\\n    -State "enabled"`
    },
    "dwight-admin": {
        title: "Enforce MFA and Revoke App Passwords for Dwight Schrute",
        platform: "Microsoft Entra ID",
        desc: "Dwight Schrute is a Global Admin without MFA registered and has active app passwords that bypass authentication policies.",
        steps: [
            "Force MFA registration: In Microsoft Entra Admin Center, go to Users > Active Users > Select Dwight > MFA settings, and enforce MFA registration.",
            "Disable App Passwords: Go to Security > Multifactor Authentication > Additional cloud-based MFA settings. Clear the 'Allow users to create app passwords to sign in to non-browser apps' checkbox.",
            "Revoke existing app passwords: Go to Dwight's user profile page and select 'Revoke MFA sessions' and delete all app passwords."
        ],
        codeLang: "PowerShell",
        code: `# Revoke all active user sign-in sessions\nRevoke-MgBetaUserSignInSession -UserId "dwight-user-uuid"\n\n# Audit user's authentication methods\nGet-MgBetaUserAuthenticationMethod -UserId "dwight-user-uuid"`
    },
    "entra-settings-legacy": {
        title: "Block Legacy Authentication Protocols",
        platform: "Microsoft Entra ID",
        desc: "Legacy protocols (IMAP, POP3, SMTP, MAPI) do not support MFA challenges. Attackers target these endpoints to bypass policies.",
        steps: [
            "In Entra admin center, go to Protection > Conditional Access > Policies.",
            "Create a new policy named 'Block Legacy Authentication'.",
            "Under 'Users', select 'All Users'.",
            "Under 'Cloud apps', select 'All cloud apps'.",
            "Under 'Conditions' > 'Client apps', configure 'Configure' to 'Yes'.",
            "Check 'Exchange ActiveSync clients' and 'Other clients' (POP, IMAP, SMTP, etc.).",
            "Under 'Grant', select 'Block access'.",
            "Save and enable the policy."
        ],
        codeLang: "PowerShell CLI",
        code: `# Create CA Policy to block legacy authentication client apps\n$conditions = @{\n    Applications = @{ IncludeApplications = @('All') }\n    Users = @{ IncludeUsers = @('All') }\n    ClientAppTypes = @('ExchangeActiveSync', 'Other')\n}\n$grantControls = @{\n    BuiltInControls = @('block')\n    Operator = 'OR'\n}\nNew-MgBetaIdentityConditionalAccessPolicy \\\n    -DisplayName "Block Legacy Auth Protocols" \\\n    -State "enabled" \\\n    -Conditions $conditions \\\n    -GrantControls $grantControls`
    },
    "ol-policy-1": {
        title: "Enforce MFA in OneLogin User Policies",
        platform: "OneLogin",
        desc: "The default Employee Policy permits optional MFA, allowing users to authenticate with passwords only.",
        steps: [
            "Log in to the OneLogin Admin portal.",
            "Navigate to Security > Policies and select 'Standard Employee Security Policy'.",
            "Select the 'MFA' tab.",
            "Set 'OTP Enrolled' to 'Required' (instead of Optional).",
            "Configure 'MFA Device Registration' to 'Prompt user on login until registered'."
        ],
        codeLang: "OneLogin REST API (cURL)",
        code: `curl -X PUT "https://api.us.onelogin.com/api/2/policies/policy-id-1" \\\n  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \\\n  -H "Content-Type: application/json" \\\n  -d '{\n    "mfa": {\n      "otp_enforced": "required",\n      "otp_registration": "mandatory"\n    }\n  }'`
    },
    "ol-policy-2": {
        title: "Disable HQ LAN MFA Bypass for Admins",
        platform: "OneLogin",
        desc: "Admin login policy bypasses MFA for the 'Corporate HQ LAN' IP range. Remote workers and compromised local networks can exploit this bypass.",
        steps: [
            "In OneLogin portal, navigate to Security > Policies > Administrator Login Policy.",
            "Go to the 'MFA' tab.",
            "Under 'MFA Bypass', locate the IP range bypass setting.",
            "Remove 'Corporate HQ LAN' from the exception range or set bypass to 'None'.",
            "Save the policy."
        ],
        codeLang: "OneLogin REST API (cURL)",
        code: `curl -X PUT "https://api.us.onelogin.com/api/2/policies/policy-id-2" \\\n  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \\\n  -H "Content-Type: application/json" \\\n  -d '{\n    "mfa": {\n      "trusted_network_bypass": "none"\n    }\n  }'`
    },
    "michael-ol-admin": {
        title: "Force MFA Registration for Michael Scott",
        platform: "OneLogin",
        desc: "Super User Michael Scott has no registered MFA devices. Any credential leak allows instant bypass of MFA.",
        steps: [
            "In OneLogin portal, select Users > Users.",
            "Search for and select 'Michael Scott'.",
            "Click on the 'Authentication' tab.",
            "Click 'Send Invitation' to force OTP registration, or click 'Reset MFA' to prompt on next login.",
            "Contact the user to verify registration of a secure device (like OneLogin Protect)."
        ],
        codeLang: "OneLogin REST API (cURL)",
        code: `# Trigger MFA reset / registration prompt for user-id\ncurl -X PUT "https://api.us.onelogin.com/api/2/users/michael-user-id/otp_devices" \\\n  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \\\n  -d '{"action": "reset"}'`
    }
};

// ==========================================================================
// FETCH COMPLIANCE REPORT FROM WORKER BACKEND
// ==========================================================================
async function fetchScanReport() {
    try {
        const response = await fetch("/api/scan");
        if (!response.ok) {
            throw new Error(`Server returned status code: ${response.status}`);
        }
        const data = await response.json();
        currentReport = data;
        return data;
    } catch (err) {
        showToast(`Worker API error: ${err.message}`, "error");
        console.error("Audit query failed:", err);
        return null;
    }
}

// ==========================================================================
// RENDER INTERFACE COMPONENT
// ==========================================================================
function renderUI() {
    if (!currentReport) return;

    const violations = currentReport.violations || [];
    const metrics = currentReport.metrics || { score: 100, criticalCount: 0, exclusionsCount: 0, adminsCount: 0, weakFactorsCount: 0, totalUsers: 0, mfaEnrolledUsers: 0 };

    // 1. Render Status Banner and Badge
    const warnBanner = document.getElementById("warning-diagnostic-banner");
    const warnMsg = document.getElementById("warning-diagnostic-msg");
    const statusText = document.getElementById("data-status-text");
    const statusDot = document.getElementById("data-status-dot");

    // Check if any scan reports warning errors
    const entraLoaded = !currentReport.warnings.some(w => w.includes("Entra") || w.includes("Microsoft"));
    const olLoaded = !currentReport.warnings.some(w => w.includes("OneLogin"));

    // Update Secrets Indicators in Credentials Tab
    const secretEntraIndicator = document.getElementById("secret-status-entra");
    const secretOlIndicator = document.getElementById("secret-status-onelogin");

    if (secretEntraIndicator) {
        if (entraLoaded) {
            secretEntraIndicator.innerHTML = `<span class="status-dot bg-success" style="width:8px; height:8px; display:inline-block; border-radius:50%; margin-right:5px;"></span> Loaded`;
            secretEntraIndicator.style.color = "var(--success)";
        } else {
            secretEntraIndicator.innerHTML = `<span class="status-dot bg-warning" style="width:8px; height:8px; display:inline-block; border-radius:50%; margin-right:5px;"></span> Not Loaded`;
            secretEntraIndicator.style.color = "var(--warning)";
        }
    }

    if (secretOlIndicator) {
        if (olLoaded) {
            secretOlIndicator.innerHTML = `<span class="status-dot bg-success" style="width:8px; height:8px; display:inline-block; border-radius:50%; margin-right:5px;"></span> Loaded`;
            secretOlIndicator.style.color = "var(--success)";
        } else {
            secretOlIndicator.innerHTML = `<span class="status-dot bg-warning" style="width:8px; height:8px; display:inline-block; border-radius:50%; margin-right:5px;"></span> Not Loaded`;
            secretOlIndicator.style.color = "var(--warning)";
        }
    }

    if (currentReport.isDemoMode) {
        warnBanner.style.display = "flex";
        // Combine warnings
        warnMsg.innerHTML = currentReport.warnings.map(w => `• ${w}`).join("<br/>");
        
        statusText.textContent = "Demo Sandbox Mode";
        statusDot.className = "badge-dot pulse-green";
        statusDot.style.backgroundColor = "var(--warning)";
    } else {
        warnBanner.style.display = "none";
        statusText.textContent = "Live Secure Sync";
        statusDot.className = "badge-dot pulse-green";
        statusDot.style.backgroundColor = "var(--success)";
    }

    // 2. Render Overview Score
    document.getElementById("overall-score-val").textContent = metrics.score;
    
    // Animate overall score ring
    const ring = document.getElementById("overall-score-ring");
    const radius = ring.r.baseVal.value;
    const circumference = 2 * Math.PI * radius;
    ring.style.strokeDasharray = circumference;
    const offset = circumference - (metrics.score / 100) * circumference;
    ring.style.strokeDashoffset = offset;

    const scoreGrade = document.getElementById("overall-score-grade");
    if (metrics.score >= 85) {
        ring.style.stroke = "var(--success)";
        scoreGrade.textContent = "Secure / Compliant";
        scoreGrade.style.color = "var(--success)";
        scoreGrade.style.borderColor = "var(--success-border)";
        scoreGrade.style.backgroundColor = "rgba(16, 185, 129, 0.08)";
    } else if (metrics.score >= 60) {
        ring.style.stroke = "var(--warning)";
        scoreGrade.textContent = "Moderate Risk";
        scoreGrade.style.color = "var(--warning)";
        scoreGrade.style.borderColor = "var(--warning-border)";
        scoreGrade.style.backgroundColor = "rgba(245, 158, 11, 0.08)";
    } else {
        ring.style.stroke = "var(--danger)";
        scoreGrade.textContent = "Critical Danger";
        scoreGrade.style.color = "#ff6b6b";
        scoreGrade.style.borderColor = "var(--danger-border)";
        scoreGrade.style.backgroundColor = "rgba(239, 68, 68, 0.08)";
    }

    // Update KPI panels
    document.getElementById("kpi-critical-count").textContent = metrics.criticalCount;
    document.getElementById("kpi-critical-val").textContent = `${metrics.criticalCount} MFA Bypasses`;
    document.getElementById("kpi-critical-progress").style.width = `${Math.min(100, metrics.criticalCount * 20)}%`;

    document.getElementById("kpi-exclusions-count").textContent = metrics.exclusionsCount;
    document.getElementById("kpi-exclusions-val").textContent = `${metrics.exclusionsCount} Policy Exclusions`;
    document.getElementById("kpi-exclusions-progress").style.width = `${Math.min(100, metrics.exclusionsCount * 15)}%`;

    document.getElementById("kpi-admins-count").textContent = metrics.adminsCount;
    document.getElementById("kpi-admins-val").textContent = `${metrics.adminsCount} Privileged Users`;
    document.getElementById("kpi-admins-progress").style.width = `${Math.min(100, metrics.adminsCount * 25)}%`;

    // 3. Render Chart Donuts
    const totalSecuredPct = metrics.totalUsers > 0 ? Math.round((metrics.mfaEnrolledUsers / metrics.totalUsers) * 100) : 0;
    document.getElementById("donut-enrolled-pct").textContent = `${totalSecuredPct}%`;
    document.getElementById("lbl-leg-enrolled").textContent = metrics.mfaEnrolledUsers;
    document.getElementById("lbl-leg-missing").textContent = metrics.totalUsers - metrics.mfaEnrolledUsers;

    const donutCircumference = 2 * Math.PI * 35; // r=35
    const enrolledSeg = document.getElementById("donut-segment-enrolled");
    const unenrolledSeg = document.getElementById("donut-segment-unenrolled");

    const enrolledOffset = donutCircumference - (totalSecuredPct / 100) * donutCircumference;
    enrolledSeg.style.strokeDasharray = donutCircumference;
    enrolledSeg.style.strokeDashoffset = enrolledOffset;

    const unenrolledPct = 100 - totalSecuredPct;
    unenrolledSeg.style.strokeDasharray = donutCircumference;
    unenrolledSeg.style.strokeDashoffset = donutCircumference - (unenrolledPct / 100) * donutCircumference;
    
    const rotationAngle = (totalSecuredPct / 100) * 360 - 90;
    unenrolledSeg.style.transform = `rotate(${rotationAngle}deg)`;

    // Threat Matrix Horizontal Bars
    const categories = { exclusions: 0, legacy: 0, admins: 0, weak: 0 };
    violations.forEach(v => {
        if (v.title.includes("Exclusion") || v.title.includes("Bypass")) categories.exclusions++;
        if (v.title.includes("Legacy") || v.title.includes("Protocols")) categories.legacy++;
        if (v.title.includes("Admin") || v.title.includes("Unenrolled")) categories.admins++;
        if (v.title.includes("Weak")) categories.weak++;
    });
    
    document.getElementById("val-matrix-exclusions").textContent = `${categories.exclusions} Findings`;
    document.getElementById("bar-exclusions").style.width = `${Math.min(100, categories.exclusions * 15)}%`;

    document.getElementById("val-matrix-legacy").textContent = `${categories.legacy} Findings`;
    document.getElementById("bar-legacy").style.width = `${Math.min(100, categories.legacy * 25)}%`;

    document.getElementById("val-matrix-admins").textContent = `${categories.admins} Findings`;
    document.getElementById("bar-admins").style.width = `${Math.min(100, categories.admins * 25)}%`;

    document.getElementById("val-matrix-weak").textContent = `${categories.weak} Findings`;
    document.getElementById("bar-weak").style.width = `${Math.min(100, categories.weak * 25)}%`;

    // 4. Render Active Configuration Violations Table
    const violationsBody = document.getElementById("violations-list");
    violationsBody.innerHTML = "";

    const filteredViolations = violations.filter(v => {
        if (currentFilter === 'all') return true;
        if (currentFilter === 'entra' && v.platform === "Microsoft Entra ID") return true;
        if (currentFilter === 'onelogin' && v.platform === "OneLogin") return true;
        return false;
    });

    if (filteredViolations.length === 0) {
        violationsBody.innerHTML = `<tr><td colspan="6" class="text-center">No active violations detected. Clean scan!</td></tr>`;
    } else {
        filteredViolations.forEach(v => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><strong>${v.title}</strong></td>
                <td><span class="badge ${v.platform.includes('Entra') ? 'badge-info' : 'badge-warning'}">${v.platform}</span></td>
                <td><span class="text-secondary">${v.scope}</span></td>
                <td><p class="desc-text-sm no-margin">${v.threat}</p></td>
                <td><span class="badge ${v.severity === 'critical' ? 'badge-danger' : 'badge-warning'}">${v.severity}</span></td>
                <td>
                    <button class="btn btn-secondary-sm btn-remed-shortcut" data-id="${v.id}">
                        Fix Guide
                    </button>
                </td>
            `;
            violationsBody.appendChild(tr);
        });
    }

    // 5. Render Entra ID Sub-Tab Content
    const entraReport = currentReport.entra;
    if (entraReport) {
        document.getElementById("entra-tenant-meta").innerHTML = `Tenant Domain: <strong>${entraReport.tenant}</strong> | Policies Evaluated: <span class="badge badge-normal">${entraReport.policies.length} Policies</span>`;
        document.getElementById("entra-ca-count").textContent = entraReport.policies.length;
        document.getElementById("entra-users-count").textContent = entraReport.users.length;
        document.getElementById("entra-settings-count").textContent = entraReport.settings.length;
        document.getElementById("entra-risk-status").textContent = `Entra Score: ${entraLoaded ? "Sync active" : "Demo Data"}`;

        // Entra CA Table
        const entraCaBody = document.getElementById("entra-ca-table-body");
        entraCaBody.innerHTML = "";
        entraReport.policies.forEach(p => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><strong>${p.displayName}</strong></td>
                <td><span class="badge ${p.state === 'enabled' ? 'badge-success' : (p.state === 'disabled' ? 'badge-danger' : 'badge-warning')}">${p.state}</span></td>
                <td><span class="text-secondary">${p.users}</span></td>
                <td><span class="text-muted">${p.resources}</span></td>
                <td><span class="text-muted">${p.controls}</span></td>
                <td><p class="desc-text-sm no-margin">${p.findings}</p></td>
                <td><span class="badge ${p.severity === 'critical' ? 'badge-danger' : (p.severity === 'warning' ? 'badge-warning' : 'badge-success')}">${p.severity}</span></td>
            `;
            entraCaBody.appendChild(tr);
        });

        // Entra Users Table
        const entraUsersBody = document.getElementById("entra-users-table-body");
        entraUsersBody.innerHTML = "";
        entraReport.users.forEach(u => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><strong>${u.upn}</strong></td>
                <td><span class="text-secondary">${u.roles}</span></td>
                <td><span class="badge ${u.mfaRegistered.startsWith('Yes') ? 'badge-success' : 'badge-danger'}">${u.mfaRegistered}</span></td>
                <td><span class="text-muted">${u.mfaEnforced}</span></td>
                <td><span class="badge ${u.appPasswords.startsWith('Yes') ? 'badge-danger' : 'badge-normal'}">${u.appPasswords}</span></td>
                <td><p class="desc-text-sm no-margin">${u.findings}</p></td>
                <td><span class="badge ${u.severity === 'critical' ? 'badge-danger' : 'badge-warning'}">${u.severity}</span></td>
            `;
            entraUsersBody.appendChild(tr);
        });

        // Entra Settings Table
        const entraSettingsBody = document.getElementById("entra-settings-table-body");
        entraSettingsBody.innerHTML = "";
        entraReport.settings.forEach(s => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><strong>${s.name}</strong></td>
                <td><span class="text-secondary">${s.state}</span></td>
                <td><span class="text-muted">${s.recommended}</span></td>
                <td><span class="badge ${s.result === 'Compliant' ? 'badge-success' : 'badge-danger'}">${s.result}</span></td>
                <td><p class="desc-text-sm no-margin">${s.implication}</p></td>
                <td><span class="badge ${s.severity === 'critical' ? 'badge-danger' : 'badge-warning'}">${s.severity}</span></td>
            `;
            entraSettingsBody.appendChild(tr);
        });
    }

    // 6. Render OneLogin Sub-Tab Content
    const olReport = currentReport.onelogin;
    if (olReport) {
        document.getElementById("onelogin-domain-meta").innerHTML = `Subdomain: <strong>${olReport.subdomain}</strong> | Active Rules Check: <span class="badge badge-normal">${olReport.policies.length} Policies</span>`;
        document.getElementById("onelogin-policies-count").textContent = olReport.policies.length;
        document.getElementById("onelogin-users-count").textContent = olReport.users.length;
        document.getElementById("onelogin-risk-status").textContent = `OneLogin: ${olLoaded ? "Sync active" : "Demo Data"}`;

        // OneLogin Policies Table
        const olPoliciesBody = document.getElementById("onelogin-policies-table-body");
        olPoliciesBody.innerHTML = "";
        olReport.policies.forEach(p => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><strong>${p.name}</strong></td>
                <td><span class="badge ${p.mfaEnforced === 'Required' ? 'badge-success' : (p.mfaEnforced === 'Optional' ? 'badge-warning' : 'badge-danger')}">${p.mfaEnforced}</span></td>
                <td><span class="text-secondary">${p.otpRegistration}</span></td>
                <td><span class="text-muted">${p.networkBypass}</span></td>
                <td><p class="desc-text-sm no-margin">${p.vulnerabilities}</p></td>
                <td><span class="badge ${p.severity === 'critical' ? 'badge-danger' : (p.severity === 'warning' ? 'badge-warning' : 'badge-success')}">${p.severity}</span></td>
            `;
            olPoliciesBody.appendChild(tr);
        });

        // OneLogin Users Table
        const olUsersBody = document.getElementById("onelogin-users-table-body");
        olUsersBody.innerHTML = "";
        olReport.users.forEach(u => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><strong>${u.username}</strong></td>
                <td><span class="badge ${u.status === 'Active' ? 'badge-success' : 'badge-normal'}">${u.status}</span></td>
                <td><span class="text-secondary">${u.policy}</span></td>
                <td><span class="badge ${u.mfaDevices === 'None Enrolled' ? 'badge-danger' : 'badge-success'}">${u.mfaDevices}</span></td>
                <td><p class="desc-text-sm no-margin">${u.bypassRisk}</p></td>
                <td><span class="badge ${u.severity === 'critical' ? 'badge-danger' : 'badge-warning'}">${u.severity}</span></td>
            `;
            olUsersBody.appendChild(tr);
        });
    }

    // 7. Render Remediation Selector list
    buildRemediationMenu(violations);
}

function buildRemediationMenu(violations) {
    const list = document.getElementById("remediation-menu-list");
    list.innerHTML = "";

    if (violations.length === 0) {
        list.innerHTML = `<div class="empty-state">No Active Fixes Needed</div>`;
        return;
    }

    violations.forEach(v => {
        const item = document.createElement("button");
        item.className = "remediation-menu-item";
        if (selectedRemediationId === v.id) {
            item.classList.add("active");
        }
        item.dataset.id = v.id;
        item.innerHTML = `
            <span class="menu-title">${v.title}</span>
            <span class="menu-platform">
                <svg width="10" height="10" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10"/></svg>
                ${v.platform}
            </span>
        `;
        item.addEventListener("click", () => {
            selectedRemediationId = v.id;
            document.querySelectorAll(".remediation-menu-item").forEach(btn => btn.classList.remove("active"));
            item.classList.add("active");
            renderRemediationDetail(v.id);
        });
        list.appendChild(item);
    });

    // Set first active
    if (!selectedRemediationId && violations.length > 0) {
        selectedRemediationId = violations[0].id;
        const firstItem = list.querySelector(".remediation-menu-item");
        if (firstItem) {
            firstItem.classList.add("active");
            renderRemediationDetail(violations[0].id);
        }
    }
}

function renderRemediationDetail(id) {
    const panel = document.getElementById("remediation-detail-panel");
    let stepData = REMEDIATION_STEPS[id];
    
    // Attempt fuzzy matches for common names/admin references
    if (!stepData && id.includes("dwight")) stepData = REMEDIATION_STEPS["dwight-admin"];
    if (!stepData && id.includes("michael")) stepData = REMEDIATION_STEPS["michael-ol-admin"];
    if (!stepData && id.includes("legacy")) stepData = REMEDIATION_STEPS["entra-settings-legacy"];

    // Dynamic fallback builder to guarantee it is NEVER blank for live APIs
    if (!stepData && currentReport && currentReport.violations) {
        const violation = currentReport.violations.find(v => v.id === id);
        if (violation) {
            const isEntra = violation.platform.toLowerCase().includes("entra") || violation.platform.toLowerCase().includes("microsoft");
            const manualSteps = isEntra ? [
                "Open the Microsoft Entra admin center (https://entra.microsoft.com).",
                "Navigate to Identity > Protection > Conditional Access > Policies (or Identity > Users depending on finding context).",
                `Auditing finding target scope: '${violation.scope}'.`,
                "Examine why this configuration bypasses MFA (e.g. check for disabled states, report-only policy switches, or insecure exclusions).",
                "Configure the policy status to 'On' and click Save.",
                "Select 'Re-Scan Active APIs' on this dashboard to verify compliance."
            ] : [
                "Log in to your OneLogin Admin Portal.",
                "Navigate to Security > Policies (or Users > Users depending on finding context).",
                `Auditing finding target scope: '${violation.scope}'.`,
                "Check the MFA tab: ensure OTP Enrollment is set to 'Required' and that 'trusted network bypasses' are disabled or securely scoped.",
                "Save changes and run a fresh scan on this dashboard to confirm the gap is closed."
            ];

            const codeLangVal = isEntra ? "PowerShell (Graph Beta)" : "REST API (cURL)";
            const codeSnippet = isEntra ? 
                `# Connect to Graph API with admin permissions\nConnect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"\n\n# Audit or modify the policy settings\nGet-MgBetaIdentityConditionalAccessPolicy -ConditionalAccessPolicyId "${id}"` :
                `# Query specific user profile settings to inspect bypass risk\ncurl -X GET "https://api.us.onelogin.com/api/2/users?query=${encodeURIComponent(violation.scope)}" \\\n  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"`;

            stepData = {
                title: `Enforce MFA: ${violation.title}`,
                platform: violation.platform,
                desc: violation.threat,
                steps: manualSteps,
                codeLang: codeLangVal,
                code: codeSnippet
            };
        }
    }

    if (!stepData) {
        panel.innerHTML = `
            <div class="empty-state">
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"></circle><path d="M12 16v-4M12 8h.01"/></svg>
                <h3>Remediation Guide Pending</h3>
                <p>Ensure that a live environment scan has been triggered to fetch finding details.</p>
            </div>
        `;
        return;
    }

    let stepsHtml = stepData.steps.map(step => `<li>${step}</li>`).join("");

    panel.innerHTML = `
        <div class="remediation-details">
            <span class="badge ${stepData.platform.toLowerCase().includes('entra') || stepData.platform.toLowerCase().includes('microsoft') ? 'badge-info' : 'badge-warning'}" style="margin-bottom: 0.5rem;">${stepData.platform}</span>
            <h3>${stepData.title}</h3>
            <p class="issue-desc">${stepData.desc}</p>

            <div class="remediation-sections">
                <div>
                    <div class="remedy-sec-title">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 11l3 3L22 4M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>
                        Manual Portal Steps
                    </div>
                    <ol class="remedy-steps-ol">${stepsHtml}</ol>
                </div>

                <div>
                    <div class="remedy-sec-title">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>
                        Automated Script (${stepData.codeLang})
                    </div>
                    <div class="code-header">
                        <span>Terminal Command</span>
                        <button class="btn-code-copy" data-copy-target="remedy-code-box">Copy Code</button>
                    </div>
                    <pre><code class="code-block" id="remedy-code-box">${stepData.code}</code></pre>
                </div>
            </div>
        </div>
    `;

    panel.querySelector(".btn-code-copy").addEventListener("click", function() {
        const codeText = document.getElementById("remedy-code-box").textContent;
        navigator.clipboard.writeText(codeText).then(() => {
            showToast("Copied command to clipboard!", "success");
        }).catch(err => {
            showToast("Failed to copy code: " + err, "error");
        });
    });
}

// ==========================================================================
// TOAST NOTIFICATIONS UTILITY
// ==========================================================================
function showToast(message, type = "info") {
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    
    let icon = "";
    if (type === "success") icon = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>`;
    else if (type === "error") icon = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
    else icon = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`;

    toast.innerHTML = `${icon}<span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transition = "opacity 0.5s ease";
        setTimeout(() => toast.remove(), 500);
    }, 4000);
}

// ==========================================================================
// UI INTERACTIONS & CONTROLLERS SETUP
// ==========================================================================
document.addEventListener("DOMContentLoaded", async () => {
    // 1. Initial scan trigger to query worker backend
    showToast("Querying Cloudflare Worker APIs...", "info");
    const report = await fetchScanReport();
    if (report) {
        renderUI();
        showToast("Compliance report synchronized!", "success");
    } else {
        showToast("Worker returned an empty payload.", "error");
    }

    // 2. Navigation Sidebar switcher
    document.querySelectorAll(".nav-item").forEach(button => {
        button.addEventListener("click", () => {
            document.querySelectorAll(".nav-item").forEach(btn => btn.classList.remove("active"));
            document.querySelectorAll(".tab-pane").forEach(pane => pane.classList.remove("active"));

            button.classList.add("active");
            const tabId = button.dataset.tab;
            document.getElementById(`tab-${tabId}`).classList.add("active");
        });
    });

    // 3. Sub-tab controllers (inside Entra ID and OneLogin panes)
    document.querySelectorAll(".sub-tab").forEach(tab => {
        tab.addEventListener("click", () => {
            const parent = tab.closest(".tab-pane");
            parent.querySelectorAll(".sub-tab").forEach(t => t.classList.remove("active"));
            parent.querySelectorAll(".sub-pane").forEach(p => p.classList.remove("active"));

            tab.classList.add("active");
            const subtabId = tab.dataset.subtab;
            document.getElementById(subtabId).classList.add("active");
        });
    });

    // 4. Integrations Secrets tabs switcher
    document.querySelectorAll(".script-tab-btn").forEach(tab => {
        tab.addEventListener("click", () => {
            const parent = tab.closest(".panel-body");
            parent.querySelectorAll(".script-tab-btn").forEach(t => t.classList.remove("active"));
            parent.querySelectorAll(".script-content").forEach(c => c.classList.remove("active"));

            tab.classList.add("active");
            const scriptId = tab.dataset.script;
            parent.querySelector(`#script-${scriptId}`).classList.add("active");
        });
    });

    // 5. Environment dropdown filter (violations table)
    document.getElementById("tenant-select").addEventListener("change", (e) => {
        currentFilter = e.target.value;
        
        if (currentFilter === 'entra') {
            document.getElementById("nav-entra").click();
        } else if (currentFilter === 'onelogin') {
            document.getElementById("nav-onelogin").click();
        } else {
            document.getElementById("nav-dashboard").click();
        }

        document.querySelectorAll(".btn-filter").forEach(btn => {
            if (btn.dataset.filter === currentFilter) {
                btn.classList.add("active");
            } else {
                btn.classList.remove("active");
            }
        });
        renderUI();
    });

    // Table quick filter buttons click
    document.querySelectorAll(".btn-filter").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".btn-filter").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            currentFilter = btn.dataset.filter;
            
            document.getElementById("tenant-select").value = currentFilter;
            renderUI();
        });
    });

    // 6. Shortcut buttons "Fix Guide" inside violations table
    document.addEventListener("click", (e) => {
        if (e.target && e.target.classList.contains("btn-remed-shortcut")) {
            const findingId = e.target.dataset.id;
            selectedRemediationId = findingId;
            
            document.getElementById("nav-remediation").click();

            const menuBtn = document.querySelector(`.remediation-menu-item[data-id="${findingId}"]`);
            if (menuBtn) {
                menuBtn.click();
            }
        }
    });

    // 7. General scan trigger actions
    const triggerScan = async () => {
        showToast("Contacting Cloudflare Worker endpoint...", "info");
        const btn = document.getElementById("btn-quick-scan");
        btn.disabled = true;
        btn.querySelector("span").textContent = "Scanning...";
        
        const freshReport = await fetchScanReport();
        if (freshReport) {
            renderUI();
            showToast("Edge Worker audit complete!", "success");
        }
        
        btn.disabled = false;
        btn.querySelector("span").textContent = "Re-Scan Active APIs";
    };
    document.getElementById("btn-quick-scan").addEventListener("click", triggerScan);

    // 8. General secret commands copy elements
    document.querySelectorAll(".btn-code-copy").forEach(btn => {
        btn.addEventListener("click", () => {
            const targetId = btn.dataset.copyTarget;
            const codeText = document.getElementById(targetId).textContent;
            navigator.clipboard.writeText(codeText).then(() => {
                showToast("Copied commands to clipboard!", "success");
            }).catch(err => {
                showToast("Failed to copy code: " + err, "error");
            });
        });
    });

    // 9. Stat Cards Click Pop-out Details Modal
    const detailsModal = document.getElementById("modal-details-overlay");
    const detailsTitle = document.getElementById("details-modal-title");
    const detailsBody = document.getElementById("details-modal-body");

    const openDetailsModal = (title, bodyHtml) => {
        detailsTitle.textContent = title;
        detailsBody.innerHTML = bodyHtml;
        detailsModal.classList.add("active");
    };

    const closeDetailsModal = () => {
        detailsModal.classList.remove("active");
    };

    document.getElementById("btn-close-details-modal").addEventListener("click", closeDetailsModal);
    document.getElementById("btn-close-details-footer").addEventListener("click", closeDetailsModal);

    document.getElementById("card-click-score").addEventListener("click", () => {
        if (!currentReport) return;
        const metrics = currentReport.metrics;
        let html = `
            <div style="text-align: center; margin-bottom: 1.5rem;">
                <div style="font-size: 3rem; font-weight: 800; color: var(--success);">${metrics.score}%</div>
                <div style="font-size: 0.9rem; color: var(--text-secondary);">Current Security Health score</div>
            </div>
            <div class="panel-header" style="padding: 0; margin-bottom: 0.75rem;">
                <h4>MFA Guard Score Audit Rules</h4>
            </div>
            <p class="desc-text-sm" style="margin-bottom: 1rem;">The score is derived out of 100 points, applying deductions for every active security gap detected in your tenant configurations:</p>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Rule / Check Case</th>
                        <th>Deduction</th>
                        <th>Condition Flag</th>
                    </tr>
                </thead>
                <tbody>
                    <tr><td><strong>Disabled CA Policies</strong></td><td style="color:var(--danger)">-15 Points</td><td>Each disabled policy targeting critical roles</td></tr>
                    <tr><td><strong>Report-Only CA Policies</strong></td><td style="color:var(--warning)">-5 Points</td><td>CA Policies not fully enforced</td></tr>
                    <tr><td><strong>Unenrolled Admin Accounts</strong></td><td style="color:var(--danger)">-20 Points</td><td>Admin profiles lacking registered MFA</td></tr>
                    <tr><td><strong>MFA Policy Exclusions</strong></td><td style="color:var(--warning)">-8 Points</td><td>Exemptions granted to security groups</td></tr>
                    <tr><td><strong>App Passwords Enrolled</strong></td><td style="color:var(--danger)">-5 Points</td><td>Bypasses Conditional Access rules</td></tr>
                    <tr><td><strong>Legacy Authentication Active</strong></td><td style="color:var(--danger)">-15 Points</td><td>Endpoints like IMAP/POP allowed</td></tr>
                    <tr><td><strong>Weak MFA Factors</strong></td><td style="color:var(--info)">-3 Points</td><td>SMS/Voice OTP allowed for access</td></tr>
                </tbody>
            </table>
        `;
        openDetailsModal("MFA Guard Score Breakdown", html);
    });

    document.getElementById("card-click-critical").addEventListener("click", () => {
        if (!currentReport) return;
        const violations = currentReport.violations.filter(v => v.severity === "critical");
        let html = `
            <p class="desc-text-sm" style="margin-bottom: 1rem;">Active critical issues that allow authentication bypass without MFA. Fix immediately:</p>
        `;
        if (violations.length === 0) {
            html += `<div class="empty-state">No critical vulnerabilities detected.</div>`;
        } else {
            html += `
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Violation</th>
                            <th>Platform</th>
                            <th>Threat Details</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            violations.forEach(v => {
                html += `
                    <tr>
                        <td><strong>${v.title}</strong></td>
                        <td><span class="badge badge-danger">${v.platform}</span></td>
                        <td><p class="desc-text-sm no-margin" style="color:var(--text-secondary)">${v.threat}</p></td>
                    </tr>
                `;
            });
            html += `</tbody></table>`;
        }
        openDetailsModal("Critical Vulnerabilities Detail", html);
    });

    document.getElementById("card-click-exclusions").addEventListener("click", () => {
        if (!currentReport) return;
        const exclusionsList = currentReport.violations.filter(v => 
            v.title.toLowerCase().includes("exclusion") || 
            v.title.toLowerCase().includes("bypass") || 
            v.scope.toLowerCase().includes("exclusion") || 
            v.scope.toLowerCase().includes("exclude")
        );
        let html = `
            <p class="desc-text-sm" style="margin-bottom: 1rem;">Active rules that exclude accounts, groups, or ranges from MFA checks:</p>
        `;
        if (exclusionsList.length === 0) {
            html += `<div class="empty-state">No active exclusions identified.</div>`;
        } else {
            html += `
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Exclusion Detail</th>
                            <th>Platform</th>
                            <th>Threat Profile</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            exclusionsList.forEach(v => {
                html += `
                    <tr>
                        <td><strong>${v.title}</strong></td>
                        <td><span class="badge badge-warning">${v.platform}</span></td>
                        <td><p class="desc-text-sm no-margin" style="color:var(--text-secondary)">${v.threat}</p></td>
                    </tr>
                `;
            });
            html += `</tbody></table>`;
        }
        openDetailsModal("MFA Exclusions Audit", html);
    });

    document.getElementById("card-click-admins").addEventListener("click", () => {
        if (!currentReport) return;
        const adminList = currentReport.violations.filter(v => 
            v.title.toLowerCase().includes("admin") || 
            v.title.toLowerCase().includes("super") || 
            v.scope.toLowerCase().includes("admin")
        );
        let html = `
            <p class="desc-text-sm" style="margin-bottom: 1rem;">Identified admin accounts at risk (missing MFA registration or bypassing controls):</p>
        `;
        if (adminList.length === 0) {
            html += `<div class="empty-state">All administrator accounts are secure.</div>`;
        } else {
            html += `
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Admin Account Details</th>
                            <th>Platform</th>
                            <th>Risk Assessment</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            adminList.forEach(v => {
                html += `
                    <tr>
                        <td><strong>${v.title}</strong></td>
                        <td><span class="badge ${v.platform.includes('Entra') ? 'badge-info' : 'badge-warning'}">${v.platform}</span></td>
                        <td><p class="desc-text-sm no-margin" style="color:var(--text-secondary)">${v.threat}</p></td>
                    </tr>
                `;
            });
            html += `</tbody></table>`;
        }
        openDetailsModal("Admin Accounts Risk Audit", html);
    });

    document.getElementById("panel-click-coverage").addEventListener("click", () => {
        if (!currentReport) return;
        
        let missingMfaUsers = [];
        if (currentReport.entra && currentReport.entra.users) {
            currentReport.entra.users.forEach(u => {
                if (u.mfaRegistered === "No") {
                    missingMfaUsers.push({
                        identity: u.upn,
                        platform: "Microsoft Entra ID",
                        role: u.roles,
                        reason: u.findings
                    });
                }
            });
        }
        if (currentReport.onelogin && currentReport.onelogin.users) {
            currentReport.onelogin.users.forEach(u => {
                if (u.mfaDevices === "None Enrolled") {
                    missingMfaUsers.push({
                        identity: u.username,
                        platform: "OneLogin",
                        role: u.status === "Active" ? "Active User" : "Suspended",
                        reason: u.bypassRisk
                    });
                }
            });
        }

        let html = `
            <p class="desc-text-sm" style="margin-bottom: 1rem;">Users currently missing registered MFA verification factors:</p>
        `;
        if (missingMfaUsers.length === 0) {
            html += `<div class="empty-state">All active users have registered MFA.</div>`;
        } else {
            html += `
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>User Identity</th>
                            <th>Platform</th>
                            <th>Status / Role</th>
                            <th>MFA Alert Reason</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            missingMfaUsers.forEach(u => {
                html += `
                    <tr>
                        <td><strong>${u.identity}</strong></td>
                        <td><span class="badge ${u.platform.includes('Entra') ? 'badge-info' : 'badge-warning'}">${u.platform}</span></td>
                        <td><p class="desc-text-sm no-margin" style="color:var(--text-secondary)">${u.role}</p></td>
                        <td><p class="desc-text-sm no-margin" style="color:var(--danger); font-size:0.8rem;">${u.reason}</p></td>
                    </tr>
                `;
            });
            html += `</tbody></table>`;
        }
        openDetailsModal("MFA Missing Registration List", html);
    });

    document.getElementById("panel-click-risk").addEventListener("click", () => {
        if (!currentReport) return;
        const violations = currentReport.violations;
        
        // Group findings by threat risk category
        const bypassIssues = violations.filter(v => 
            v.severity === "critical" || 
            v.title.toLowerCase().includes("disabled") || 
            v.title.toLowerCase().includes("bypass") || 
            v.title.toLowerCase().includes("legacy")
        );
        const policyIssues = violations.filter(v => 
            v.severity === "high" || 
            v.title.toLowerCase().includes("exclusion") || 
            v.title.toLowerCase().includes("optional") || 
            v.title.toLowerCase().includes("report-only")
        );
        const userIssues = violations.filter(v => 
            v.title.toLowerCase().includes("unregistered") || 
            v.title.toLowerCase().includes("unenrolled") || 
            v.title.toLowerCase().includes("lacks mfa")
        );
        const weakFactorIssues = violations.filter(v => 
            v.title.toLowerCase().includes("weak") || 
            v.title.toLowerCase().includes("sms") || 
            v.title.toLowerCase().includes("voice")
        );

        let html = `
            <p class="desc-text-sm" style="margin-bottom: 1rem;">Summary of configuration risks categorized by severity and impact:</p>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Risk Category</th>
                        <th>Impact Level</th>
                        <th>Count</th>
                        <th>Description of Bypass Potential</th>
                    </tr>
                </thead>
                <tbody>
                    <tr style="background: rgba(220,53,69,0.05);">
                        <td><strong>Direct MFA Bypasses</strong></td>
                        <td><span class="badge badge-danger">Critical</span></td>
                        <td><strong>${bypassIssues.length}</strong></td>
                        <td>Disabled policies, legacy authentication protocols, or IP exemptions allowing login without MFA.</td>
                    </tr>
                    <tr style="background: rgba(255,193,7,0.05);">
                        <td><strong>MFA Policy Exclusions</strong></td>
                        <td><span class="badge badge-warning">High</span></td>
                        <td><strong>${policyIssues.length}</strong></td>
                        <td>Conditional Access policies with active group exclusions or optional enrollment states.</td>
                    </tr>
                    <tr style="background: rgba(23,162,184,0.05);">
                        <td><strong>Unenrolled Admin Accounts</strong></td>
                        <td><span class="badge badge-info">Medium</span></td>
                        <td><strong>${userIssues.length}</strong></td>
                        <td>High-privilege administrators who have not registered a physical authentication factor.</td>
                    </tr>
                    <tr>
                        <td><strong>Weak MFA Factors</strong></td>
                        <td><span class="badge" style="background:var(--bg-secondary); color:var(--text-secondary);">Low</span></td>
                        <td><strong>${weakFactorIssues.length}</strong></td>
                        <td>Users utilizing SMS or Voice OTP, susceptible to SIM-swapping or phishing.</td>
                    </tr>
                </tbody>
            </table>
        `;
        openDetailsModal("Security Risk Category Analysis", html);
    });
});
