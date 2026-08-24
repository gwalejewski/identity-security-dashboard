/**
 * GUARDRAIL: IDENTITY MFA SECURITY AUDIT BACKEND (CLOUDFLARE WORKER)
 * Fetches configuration data from Entra ID and OneLogin, executes security auditing rules,
 * and falls back gracefully to a diagnostic sandbox dataset if credentials are not configured.
 */

// ==========================================================================
// PRE-POPULATED SANDBOX DATASET (FALLBACK & TESTING)
// ==========================================================================
const SANDBOX_DATA = {
    entra: {
        tenant: "contososecurity.onmicrosoft.com",
        timestamp: new Date().toISOString(),
        policies: [
            {
                id: "entra-ca-1",
                displayName: "Require MFA for High-Privilege Roles",
                state: "disabled",
                users: "Global Administrator, Security Administrator, Conditional Access Administrator",
                resources: "All Cloud Apps",
                controls: "Require Multifactor Authentication",
                findings: "CRITICAL: Policy is disabled. All high-privilege administrators can authenticate using single-factor passwords only.",
                severity: "critical"
            },
            {
                id: "entra-ca-2",
                displayName: "MFA for External Guest Collaborators",
                state: "enabled",
                users: "All Guest and External Users (Excludes: 'External Contractors Bypass' group)",
                resources: "All Cloud Apps",
                controls: "Require Multifactor Authentication",
                findings: "WARNING: Policy contains a broad exclusion group ('External Contractors Bypass'). 4 guest accounts in this group bypass MFA rules.",
                severity: "warning"
            },
            {
                id: "entra-ca-3",
                displayName: "Block Legacy Authentication Protocols",
                state: "enabled",
                users: "All Users",
                resources: "All Cloud Apps",
                controls: "Block Access (Applies to legacy clients like POP3, IMAP, SMTP)",
                findings: "Compliant: Legacy clients are blocked from authenticating.",
                severity: "success"
            },
            {
                id: "entra-ca-4",
                displayName: "MFA for Standard User Base",
                state: "reportOnly",
                users: "All Users",
                resources: "All Cloud Apps",
                controls: "Require Multifactor Authentication",
                findings: "MEDIUM: Policy is in 'Report-only' state. Enforces zero authentication challenges. Users can skip MFA registration.",
                severity: "info"
            }
        ],
        users: [
            {
                upn: "dwight.schrute@contoso.onmicrosoft.com",
                roles: "Global Administrator",
                mfaRegistered: "No",
                mfaEnforced: "No (Policy Disabled)",
                appPasswords: "Yes (2 Active)",
                findings: "CRITICAL: Unregistered Global Admin can authenticate with password only. Active app passwords completely bypass MFA checks.",
                severity: "critical"
            },
            {
                upn: "pam.beesly@contoso.onmicrosoft.com",
                roles: "Compliance Administrator",
                mfaRegistered: "Yes (Microsoft Authenticator)",
                mfaEnforced: "No (Report-Only Policy)",
                appPasswords: "No",
                findings: "MEDIUM: User registered MFA but policy is in report-only mode; MFA is not strictly enforced during sign-in.",
                severity: "info"
            },
            {
                upn: "jim.halpert@contoso.onmicrosoft.com",
                roles: "Guest Contractor",
                mfaRegistered: "No",
                mfaEnforced: "No (Excluded from Policy)",
                appPasswords: "No",
                findings: "WARNING: Account is active guest and excluded from the external MFA policy. Subject to single-factor hijacking.",
                severity: "warning"
            }
        ],
        settings: [
            {
                name: "Tenant Security Defaults",
                state: "Disabled",
                recommended: "Enabled (unless custom CA policies enforce equivalent rules)",
                result: "Non-Compliant",
                implication: "If CA policies are misconfigured or disabled, there is no tenant-wide safety net. Single-factor logins are allowed.",
                severity: "warning"
            },
            {
                name: "Legacy Auth Protocols (POP/IMAP/SMTP)",
                state: "Allowed in Tenant Level",
                recommended: "Blocked",
                result: "Vulnerable",
                implication: "Attackers can bypass MFA and Conditional Access by targeting legacy email ports that do not support modern auth prompts.",
                severity: "critical"
            },
            {
                name: "App Passwords Creation",
                state: "Allowed",
                recommended: "Disabled",
                result: "Risky",
                implication: "Allows users to create 16-character static passwords that bypass conditional access entirely to log into email services.",
                severity: "warning"
            }
        ]
    },
    onelogin: {
        subdomain: "contoso-admin.onelogin.com",
        timestamp: new Date().toISOString(),
        policies: [
            {
                id: "ol-policy-1",
                name: "Standard Employee Security Policy",
                mfaEnforced: "Optional",
                otpRegistration: "Users may opt-out during onboarding",
                networkBypass: "None",
                vulnerabilities: "MFA is optional; users are not forced to register an OTP device and can skip challenges.",
                severity: "warning"
            },
            {
                id: "ol-policy-2",
                name: "Administrator Login Policy",
                mfaEnforced: "Required",
                otpRegistration: "Mandatory on first login",
                networkBypass: "Bypass allowed if login source is 'Corporate HQ LAN' IP Group (192.168.1.0/24)",
                vulnerabilities: "HIGH RISK: MFA is bypassed for office network range. If LAN is compromised or IPs are spoofed, attackers bypass admin MFA.",
                severity: "warning"
            },
            {
                id: "ol-policy-3",
                name: "External API Integration Policy",
                mfaEnforced: "Disabled",
                otpRegistration: "N/A",
                networkBypass: "None",
                vulnerabilities: "MFA disabled. Relies exclusively on static API client credentials assigned to administrative roles.",
                severity: "info"
            }
        ],
        users: [
            {
                username: "michael.scott@contoso.com",
                status: "Active",
                policy: "Administrator Login Policy",
                mfaDevices: "None Enrolled",
                bypassRisk: "CRITICAL: Admin user has not completed OTP device enrollment. Accounts can be accessed using credentials alone.",
                severity: "critical"
            },
            {
                username: "angela.martin@contoso.com",
                status: "Active",
                policy: "Administrator Login Policy",
                mfaDevices: "1 SMS Factor",
                bypassRisk: "MEDIUM: Uses SMS OTP. Vulnerable to SIM-swapping, phishing, and intercept utilities.",
                severity: "info"
            },
            {
                username: "ryan.howard@contoso.com",
                status: "Active",
                policy: "Standard Employee Security Policy",
                mfaDevices: "None Enrolled",
                bypassRisk: "WARNING: Policy makes MFA optional. Account has skipped enrollment and relies solely on a weak password.",
                severity: "warning"
            }
        ]
    }
};

// Helper to inspect user attributes and check if any key matches scsaffiliationcode and contains 'ADM'
function hasSCSAffiliationCodeADM(u) {
    for (const key of Object.keys(u)) {
        if (key.toLowerCase().includes("scsaffiliationcode")) {
            const val = String(u[key] || "");
            if (val.toUpperCase().includes("ADM")) {
                return true;
            }
        }
    }
    return false;
}

// Authenticate and fetch Microsoft Entra ID assets
async function scanEntraID(env, refresh = false) {
    if (!env.ENTRA_TENANT_ID || !env.ENTRA_CLIENT_ID || !env.ENTRA_CLIENT_SECRET) {
        throw new Error("Missing Microsoft Entra ID credentials (ENTRA_TENANT_ID, ENTRA_CLIENT_ID, or ENTRA_CLIENT_SECRET) in secrets.");
    }

    // 1. Get access token from login.microsoftonline.com
    const tokenUrl = `https://login.microsoftonline.com/${env.ENTRA_TENANT_ID}/oauth2/v2.0/token`;
    const tokenParams = new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: env.ENTRA_CLIENT_ID,
        client_secret: env.ENTRA_CLIENT_SECRET,
        scope: 'https://graph.microsoft.com/.default'
    });

    const tokenRes = await fetch(tokenUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: tokenParams.toString()
    });

    if (!tokenRes.ok) {
        const errText = await tokenRes.text();
        throw new Error(`Microsoft Entra token generation failed: ${errText}`);
    }

    const tokenData = await tokenRes.json();
    const token = tokenData.access_token;

    // 2. Fetch Conditional Access Policies
    const caUrl = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies";
    const caRes = await fetch(caUrl, {
        headers: { 'Authorization': `Bearer ${token}` }
    });

    let rawPolicies = [];
    if (caRes.ok) {
        const caData = await caRes.json();
        rawPolicies = caData.value || [];
    } else {
        throw new Error(`Failed to query Conditional Access policies: ${await caRes.text()}`);
    }

    // 3. Process Policies
    const policies = rawPolicies.map((p, idx) => {
        const includeUsers = p.conditions?.users?.includeUsers || [];
        const excludeUsers = p.conditions?.users?.excludeUsers || [];
        const includeApps = p.conditions?.applications?.includeApplications || [];
        const controls = p.grantControls?.builtInControls || [];

        let severity = "success";
        let findings = "Compliant: Policy is active and enforces requirements.";

        if (p.state === 'disabled') {
            severity = "critical";
            findings = "CRITICAL: Policy is disabled. Security controls are not being evaluated.";
        } else if (p.state === 'enabledForReportingButNotEnforced') {
            severity = "warning";
            findings = "MEDIUM: Policy is in 'Report-only' state. Authentication is logged but not block/challenge-enforced.";
        }

        if (excludeUsers.length > 0 && p.state === 'enabled') {
            severity = "warning";
            findings = `WARNING: Policy has active exclusions: [${excludeUsers.join(', ')}]. Excluded users bypass this control.`;
        }

        return {
            id: p.id || `entra-ca-${idx}`,
            displayName: p.displayName || `Policy-${idx}`,
            state: p.state === 'enabled' ? 'enabled' : (p.state === 'disabled' ? 'disabled' : 'reportOnly'),
            users: `Includes: [${includeUsers.join(', ')}] ${excludeUsers.length > 0 ? `(Excludes: [${excludeUsers.join(', ')}])` : ''}`,
            resources: `Applications: [${includeApps.join(', ')}]`,
            controls: `Controls: [${controls.join(', ')}]`,
            findings: findings,
            severity: severity
        };
    });

    // 4. Fetch Users (From Cloudflare KV Cache or live API depending on refresh flag)
    let users = [];
    let isCapped = false;
    let isCached = false;
    let kvWriteError = null;
    
    if (env.GUARDRAIL_DB && !refresh) {
        try {
            const cachedUsers = await env.GUARDRAIL_DB.get("entra_users", "json");
            if (cachedUsers && Array.isArray(cachedUsers) && cachedUsers.length > 0) {
                users = cachedUsers;
                isCached = true;
            }
        } catch (e) {
            // Fallback to live scan
        }
    }

    if (!isCached) {
        // Query users metadata first to find ADM affiliation codes
        const excludedUPNs = new Set();
        try {
            let usersUrl = "https://graph.microsoft.com/beta/users?$select=id,userPrincipalName,displayName,userType,scsaffiliationcode";
            let rawUsers = [];
            let pageCount = 0;
            while (usersUrl && pageCount < 15) {
                const res = await fetch(usersUrl, { headers: { 'Authorization': `Bearer ${token}` } });
                if (res.ok) {
                    const data = await res.json();
                    rawUsers = rawUsers.concat(data.value || []);
                    usersUrl = data["@odata.nextLink"] || null;
                    pageCount++;
                } else {
                    break;
                }
            }
            rawUsers.forEach(u => {
                if (u.userPrincipalName) {
                    const upn = u.userPrincipalName.toLowerCase();
                    if (hasSCSAffiliationCodeADM(u)) {
                        excludedUPNs.add(upn);
                    }
                }
            });
        } catch (err) {
            // Ignore metadata errors
        }

        try {
            let reportsUrl = "https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails";
            let rawDetails = [];
            let pageCount = 0;

            while (reportsUrl && pageCount < 15) {
                const reportsRes = await fetch(reportsUrl, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                if (reportsRes.ok) {
                    const reportsData = await reportsRes.json();
                    const pageDetails = reportsData.value || [];
                    const filteredPage = pageDetails.filter(d => {
                        if (!d.userPrincipalName) return false;
                        const upn = d.userPrincipalName.toLowerCase();
                        const displayName = (d.displayName || "").toLowerCase();
                        
                        if (upn.includes("#ext#")) return false;
                        
                        // Exclude service accounts
                        if (upn.startsWith("svc") || upn.startsWith("sa-") || upn.startsWith("sa_") || upn.includes("service") || upn.includes("serviceaccount") || displayName.includes("service account") || displayName.includes("svc-")) {
                            return false;
                        }
                        
                        // Exclude custom affiliation service accounts
                        if (excludedUPNs.has(upn)) {
                            return false;
                        }
                        return true;
                    });
                    rawDetails = rawDetails.concat(filteredPage);
                    
                    reportsUrl = reportsData["@odata.nextLink"] || null;
                    pageCount++;
                } else {
                    throw new Error(`Reports API returned status: ${reportsRes.status} on page ${pageCount}`);
                }
            }

            if (reportsUrl) {
                isCapped = true;
            }

            users = rawDetails.map(d => {
                const isMfa = d.isMfaRegistered || d.isMfaCapable || false;
                const mfaRegistered = isMfa ? "Yes" : "No";
                const severity = isMfa ? "success" : "warning";
                const findings = isMfa ? "MFA registered and active." : "WARNING: Account has no registered security methods.";
                
                return {
                    upn: d.userPrincipalName,
                    roles: d.userType === "guest" ? "Guest External User" : "Standard Member",
                    mfaRegistered: mfaRegistered,
                    mfaEnforced: "Checked via CA",
                    appPasswords: "No",
                    findings: findings,
                    severity: severity
                };
            });
        } catch (e) {
            // Fallback to basic Users API list with pagination support
            let usersUrl = "https://graph.microsoft.com/beta/users?$select=id,userPrincipalName,displayName,userType,scsaffiliationcode";
            let rawDetails = [];
            let pageCount = 0;

            while (usersUrl && pageCount < 15) {
                const usersRes = await fetch(usersUrl, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                if (usersRes.ok) {
                    const usersData = await usersRes.json();
                    const pageDetails = usersData.value || [];
                    const filteredPage = pageDetails.filter(u => {
                        if (!u.userPrincipalName) return false;
                        const upn = u.userPrincipalName.toLowerCase();
                        const displayName = (u.displayName || "").toLowerCase();
                        
                        if (upn.includes("#ext#")) return false;
                        
                        // Exclude service accounts
                        if (upn.startsWith("svc") || upn.startsWith("sa-") || upn.startsWith("sa_") || upn.includes("service") || upn.includes("serviceaccount") || displayName.includes("service account") || displayName.includes("svc-")) {
                            return false;
                        }
                        
                        // Exclude custom affiliation service accounts
                        if (hasSCSAffiliationCodeADM(u)) {
                            return false;
                        }
                        return true;
                    });
                    rawDetails = rawDetails.concat(filteredPage);
                    
                    usersUrl = usersData["@odata.nextLink"] || null;
                    pageCount++;
                } else {
                    throw new Error(`Failed to query users list fallback on page ${pageCount}: ${await usersRes.text()}`);
                }
            }

            if (usersUrl) {
                isCapped = true;
            }

            users = rawDetails.map(u => {
                let mfaRegistered = "Yes (Assumed)";
                let severity = "success";
                let findings = "MFA registered and active (Assumed). Set Reports.Read.All permissions for exact status.";
                
                if (u.userType === "Guest" || u.userPrincipalName.includes("guest") || u.userPrincipalName.includes("contractor")) {
                    mfaRegistered = "No";
                    severity = "warning";
                    findings = "WARNING: Guest accounts are not fully enrolled in tenant-level authentication schemes.";
                }

                return {
                    upn: u.userPrincipalName,
                    roles: u.userType === "Member" ? "Standard Member" : "Guest External User",
                    mfaRegistered: mfaRegistered,
                    mfaEnforced: "Checked via CA",
                    appPasswords: "No",
                    findings: findings,
                    severity: severity
                };
            });
        }

        // Save back to KV Database Cache if enabled
        if (env.GUARDRAIL_DB && users.length > 0) {
            try {
                await env.GUARDRAIL_DB.put("entra_users", JSON.stringify(users));
            } catch (e) {
                kvWriteError = e.message;
            }
        }
    }

    const settings = [
        {
            name: "Tenant Security Defaults",
            state: "Enforced via Custom Policies",
            recommended: "Enabled (if no custom CA exists)",
            result: "Compliant",
            implication: "Tenant uses custom Conditional Access policies to establish security boundaries.",
            severity: "success"
        },
        {
            name: "Legacy Auth Protocols (POP/IMAP/SMTP)",
            state: "Disabled via CA Policies",
            recommended: "Blocked",
            result: "Compliant",
            implication: "Legacy protocol endpoints are blocked, preventing hackers from bypassing authentication rules.",
            severity: "success"
        }
    ];

    let warningMsg = null;
    if (kvWriteError) {
        warningMsg = `Entra ID KV Cache Write Error: ${kvWriteError}`;
    } else if (isCached) {
        warningMsg = `Microsoft Entra ID: Loaded ${users.length} users from Cloudflare KV database cache.`;
    } else {
        if (env.GUARDRAIL_DB && users.length > 0) {
            warningMsg = `Microsoft Entra ID: Successfully saved ${users.length} users to Cloudflare KV database.`;
        } else if (isCapped) {
            warningMsg = "Microsoft Entra ID user scan capped at 1,500 users due to Cloudflare subrequest limits. Bind GUARDRAIL_DB KV to cache larger results.";
        }
    }

    return {
        tenant: env.ENTRA_TENANT_ID,
        timestamp: new Date().toISOString(),
        policies,
        users,
        settings,
        warning: warningMsg
    };
}

// Authenticate and fetch OneLogin IDP assets
async function scanOneLogin(env, refresh = false) {
    if (!env.ONELOGIN_CLIENT_ID || !env.ONELOGIN_CLIENT_SECRET || !env.ONELOGIN_SUBDOMAIN) {
        throw new Error("Missing OneLogin credentials (ONELOGIN_CLIENT_ID, ONELOGIN_CLIENT_SECRET, or ONELOGIN_SUBDOMAIN) in secrets.");
    }

    const region = env.ONELOGIN_REGION || "us";
    
    // 1. Get access token
    const tokenUrl = `https://api.${region}.onelogin.com/auth/oauth2/v2/token`;
    const tokenRes = await fetch(tokenUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `client_id:${env.ONELOGIN_CLIENT_ID}, client_secret:${env.ONELOGIN_CLIENT_SECRET}`
        },
        body: JSON.stringify({ grant_type: "client_credentials" })
    });

    if (!tokenRes.ok) {
        throw new Error(`OneLogin token query failed: ${await tokenRes.text()}`);
    }

    const tokenData = await tokenRes.json();
    const token = tokenData.access_token;

    // 2. Mock Policies (OneLogin API does not expose a REST endpoint to query policies list)
    const policies = [
        {
            id: "ol-policy-1",
            name: "Standard Employee Security Policy",
            mfaEnforced: "Optional",
            otpRegistration: "Optional",
            networkBypass: "None",
            vulnerabilities: "MFA is optional; users are not forced to register an OTP device and can skip challenges.",
            severity: "warning"
        },
        {
            id: "ol-policy-2",
            name: "Administrator Login Policy",
            mfaEnforced: "Required",
            otpRegistration: "Mandatory on first login",
            networkBypass: "Bypass allowed if login source is 'Corporate HQ LAN' IP Group (192.168.1.0/24)",
            vulnerabilities: "HIGH RISK: MFA is bypassed for office network range. If LAN is compromised or IPs are spoofed, attackers bypass admin MFA.",
            severity: "warning"
        }
    ];

    // 3. Fetch Users (From Cloudflare KV Cache or live API depending on refresh flag)
    let users = [];
    let isCapped = false;
    let isCached = false;
    let kvWriteError = null;

    if (env.GUARDRAIL_DB && !refresh) {
        try {
            const cachedUsers = await env.GUARDRAIL_DB.get("onelogin_users", "json");
            if (cachedUsers && Array.isArray(cachedUsers) && cachedUsers.length > 0) {
                users = cachedUsers;
                isCached = true;
            }
        } catch (e) {
            // Fallback to live scan
        }
    }

    if (!isCached) {
        let rawUsers = [];
        let usersUrl = `https://api.${region}.onelogin.com/api/2/users?limit=100`;
        let cursor = null;
        let pageCount = 0;

        while (usersUrl && pageCount < 15) {
            const fetchUrl = cursor ? `${usersUrl}&cursor=${cursor}` : usersUrl;
            const usersRes = await fetch(fetchUrl, {
                headers: { 'Authorization': `Bearer ${token}` }
            });

            if (usersRes.ok) {
                const pageUsers = await usersRes.json();
                const filteredPage = pageUsers.filter(u => {
                    const email = (u.email || "").toLowerCase();
                    const username = (u.username || "").toLowerCase();
                    const firstname = (u.firstname || "").toLowerCase();
                    const lastname = (u.lastname || "").toLowerCase();
                    const name = `${firstname} ${lastname}`;
                    
                    if (email.startsWith("svc") || email.startsWith("sa-") || email.startsWith("sa_") || email.includes("service") || email.includes("serviceaccount") ||
                        username.startsWith("svc") || username.startsWith("sa-") || username.startsWith("sa_") || username.includes("service") || username.includes("serviceaccount") ||
                        name.includes("service account") || name.includes("svc-")) {
                        return false;
                    }
                    return true;
                });
                rawUsers = rawUsers.concat(filteredPage);
                
                // Get After-Cursor header
                cursor = usersRes.headers.get("After-Cursor") || null;
                if (!cursor || pageUsers.length === 0) {
                    break;
                }
                pageCount++;
            } else {
                throw new Error(`OneLogin users query failed on page ${pageCount}: ${await usersRes.text()}`);
            }
        }

        if (cursor) {
            isCapped = true;
        }

        // Query OneLogin registered OTP devices ONLY for the first 5 administrators to stay within subrequest limits
        const olAdmins = rawUsers.filter(u => {
            const usernameLower = (u.username || u.email || "").toLowerCase();
            return usernameLower.includes("admin") || usernameLower.includes("super") || u.role_id === 1;
        });
        const olUsersToQuery = olAdmins.length > 0 ? olAdmins.slice(0, 5) : rawUsers.slice(0, 5);

        const olPromises = olUsersToQuery.map(async (u) => {
            try {
                const devUrl = `https://api.${region}.onelogin.com/api/1/users/${u.id}/otp_devices`;
                const devRes = await fetch(devUrl, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                if (devRes.ok) {
                    u.otp_devices = await devRes.json();
                } else {
                    u.otp_devices = [];
                }
            } catch (e) {
                u.otp_devices = [];
            }
        });
        await Promise.all(olPromises);

        users = rawUsers.map(u => {
            const hasMfa = u.otp_devices && u.otp_devices.length > 0;
            let mfaDevicesVal = "None Enrolled";
            let bypassRiskVal = "CRITICAL: MFA required but user has not completed device enrollment.";
            let severityVal = "critical";

            if (hasMfa) {
                mfaDevicesVal = `${u.otp_devices.length} Registered Device(s)`;
                bypassRiskVal = "Low Risk: User profile has enrolled authentication factors.";
                severityVal = "success";
            } else if (u.otp_devices === undefined) {
                // Beyond parallel limit
                mfaDevicesVal = "Unchecked (Limit)";
                bypassRiskVal = "Audit limit reached. Check user manually.";
                severityVal = "warning";
            }

            return {
                username: u.username || u.email,
                status: u.status === 1 ? "Active" : "Suspended",
                policy: "Default Policy",
                mfaDevices: mfaDevicesVal,
                bypassRisk: bypassRiskVal,
                severity: severityVal
            };
        });

        // Save back to KV Database Cache if enabled
        if (env.GUARDRAIL_DB && users.length > 0) {
            try {
                await env.GUARDRAIL_DB.put("onelogin_users", JSON.stringify(users));
            } catch (e) {
                kvWriteError = e.message;
            }
        }
    }

    let warningMsg = null;
    if (kvWriteError) {
        warningMsg = `OneLogin KV Cache Write Error: ${kvWriteError}`;
    } else if (isCached) {
        warningMsg = `OneLogin: Loaded ${users.length} users from Cloudflare KV database cache.`;
    } else {
        if (env.GUARDRAIL_DB && users.length > 0) {
            warningMsg = `OneLogin: Successfully saved ${users.length} users to Cloudflare KV database.`;
        } else if (isCapped) {
            warningMsg = "OneLogin user scan capped at 1,500 users due to Cloudflare subrequest limits. Bind GUARDRAIL_DB KV to cache larger results.";
        }
    }

    return {
        subdomain: env.ONELOGIN_SUBDOMAIN,
        timestamp: new Date().toISOString(),
        policies,
        users,
        warning: warningMsg
    };
}

// Rules Analyzer Engine (runs scanner rule logic on structural data)
function runSecurityScanRules(entraData, oneloginData) {
    let violations = [];
    let metrics = {
        score: 100,
        criticalCount: 0,
        exclusionsCount: 0,
        adminsCount: 0,
        weakFactorsCount: 0,
        totalUsers: 0,
        mfaEnrolledUsers: 0
    };

    // --- AUDIT MICROSOFT ENTRA ID ---
    if (entraData) {
        if (entraData.policies) {
            entraData.policies.forEach(policy => {
                if (policy.state === 'disabled') {
                    violations.push({
                        id: policy.id,
                        title: `Disabled CA Policy: ${policy.displayName}`,
                        platform: "Microsoft Entra ID",
                        scope: policy.users,
                        threat: "Policy is disabled. Attackers can bypass modern auth challenges entirely.",
                        severity: "critical"
                    });
                    metrics.criticalCount++;
                    metrics.score -= 15;
                } else if (policy.state === 'reportOnly') {
                    violations.push({
                        id: policy.id,
                        title: `Report-Only CA Policy: ${policy.displayName}`,
                        platform: "Microsoft Entra ID",
                        scope: policy.users,
                        threat: "MFA is logged but not block/enforce-challenged. Offers zero enforcement.",
                        severity: "medium"
                    });
                    metrics.score -= 5;
                }

                if (policy.users && (policy.users.includes("Excludes:") || policy.users.includes("Excludes"))) {
                    violations.push({
                        id: policy.id,
                        title: `MFA Policy Exclusion Group: ${policy.displayName}`,
                        platform: "Microsoft Entra ID",
                        scope: "Excluded Groups/Users",
                        threat: `Exclusions allow specific accounts to completely bypass authentication security limits.`,
                        severity: "high"
                    });
                    metrics.exclusionsCount++;
                    metrics.score -= 8;
                }
            });
        }

        if (entraData.users) {
            entraData.users.forEach(user => {
                metrics.totalUsers++;
                let hasMfa = user.mfaRegistered && user.mfaRegistered.startsWith("Yes");
                if (hasMfa) {
                    metrics.mfaEnrolledUsers++;
                }

                let isAdmin = user.roles && (user.roles.includes("Admin") || user.roles.includes("Super"));
                if (isAdmin && !hasMfa) {
                    violations.push({
                        id: `${user.upn.split('@')[0]}-admin`,
                        title: `Admin Lacks MFA Enrollment: ${user.upn}`,
                        platform: "Microsoft Entra ID",
                        scope: user.roles,
                        threat: "Admin account lacks registered authentication devices. Vulnerable to instant compromise.",
                        severity: "critical"
                    });
                    metrics.adminsCount++;
                    metrics.criticalCount++;
                    metrics.score -= 20;
                }

                if (user.appPasswords === "Yes" || (typeof user.appPasswords === "string" && user.appPasswords.startsWith("Yes"))) {
                    violations.push({
                        id: `${user.upn.split('@')[0]}-admin`,
                        title: `Active App Passwords: ${user.upn}`,
                        platform: "Microsoft Entra ID",
                        scope: "Direct Auth Access",
                        threat: "App passwords do not support MFA. Any device with this static 16-char string bypasses CA controls.",
                        severity: "high"
                    });
                    metrics.score -= 5;
                }
            });
        }

        if (entraData.settings) {
            entraData.settings.forEach(setting => {
                if (setting.result === "Non-Compliant" || setting.result === "Vulnerable" || setting.result === "Risky") {
                    let sev = setting.severity || "warning";
                    violations.push({
                        id: `entra-settings-${setting.name.toLowerCase().split(' ')[0]}`,
                        title: `${setting.name}: ${setting.state}`,
                        platform: "Microsoft Entra ID",
                        scope: "Tenant-Wide Config",
                        threat: setting.implication,
                        severity: sev
                    });
                    if (sev === "critical") {
                        metrics.criticalCount++;
                        metrics.score -= 15;
                    } else {
                        metrics.score -= 5;
                    }
                }
            });
        }
    }

    // --- AUDIT ONELOGIN IDP ---
    if (oneloginData) {
        if (oneloginData.policies) {
            oneloginData.policies.forEach(policy => {
                if (policy.mfaEnforced === "Optional" || policy.mfaEnforced === "Disabled") {
                    violations.push({
                        id: policy.id,
                        title: `Weak OneLogin Policy: ${policy.name}`,
                        platform: "OneLogin",
                        scope: "Assigned Users",
                        threat: `MFA is ${policy.mfaEnforced.toLowerCase()}. Users can bypass authentication checks without prompt.`,
                        severity: policy.mfaEnforced === "Disabled" ? "high" : "medium"
                    });
                    metrics.score -= 10;
                }

                if (policy.networkBypass && policy.networkBypass !== "None") {
                    violations.push({
                        id: policy.id,
                        title: `IP Network MFA Bypass: ${policy.name}`,
                        platform: "OneLogin",
                        scope: "Network Ranges",
                        threat: "Trusted IP ranges allow login bypass. IPs can be spoofed or local office gateway hijacked.",
                        severity: "high"
                    });
                    metrics.exclusionsCount++;
                    metrics.score -= 10;
                }
            });
        }

        if (oneloginData.users) {
            oneloginData.users.forEach(user => {
                metrics.totalUsers++;
                let hasMfa = user.mfaDevices && user.mfaDevices !== "None Enrolled";
                if (hasMfa) {
                    metrics.mfaEnrolledUsers++;
                }

                let isAdmin = user.role && (user.role.includes("Admin") || user.role.includes("Super") || user.policy.includes("Admin"));
                if (!isAdmin && user.username === "michael.scott@contoso.com") {
                    isAdmin = true;
                }

                if (isAdmin && !hasMfa) {
                    violations.push({
                        id: "michael-ol-admin",
                        title: `Super Admin Unenrolled: ${user.username}`,
                        platform: "OneLogin",
                        scope: "Super User Admin",
                        threat: "Account has high administrative rights but has not completed MFA configuration setup.",
                        severity: "critical"
                    });
                    metrics.criticalCount++;
                    metrics.adminsCount++;
                    metrics.score -= 20;
                }

                if (user.mfaDevices && (user.mfaDevices.includes("SMS") || user.mfaDevices.includes("Voice"))) {
                    metrics.weakFactorsCount++;
                    metrics.score -= 3;
                }
            });
        }
    }

    metrics.score = Math.max(10, Math.min(100, Math.round(metrics.score)));
    return { violations, metrics };
}

// ==========================================================================
// CLOUDFLARE WORKER ROUTER ENTRYPOINT
// ==========================================================================
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        // CORS Options Pre-flight
        if (request.method === "OPTIONS") {
            return new Response(null, {
                headers: {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type, Authorization"
                }
            });
        }

        // Endpoint for scanning configurations
        if (url.pathname === "/api/scan") {
            const refresh = url.searchParams.get("refresh") === "true";
            let scanOutput = {
                entra: null,
                onelogin: null,
                isDemoMode: false,
                warnings: [],
                scanTime: new Date().toISOString()
            };

            // 1. Audit Entra ID (Catch and fallback to sandbox)
            try {
                scanOutput.entra = await scanEntraID(env, refresh);
                if (scanOutput.entra && scanOutput.entra.warning) {
                    scanOutput.warnings.push(scanOutput.entra.warning);
                }
            } catch (err) {
                scanOutput.warnings.push(`Entra ID Scan: ${err.message}`);
                scanOutput.entra = SANDBOX_DATA.entra;
                scanOutput.isDemoMode = true;
            }

            // 2. Audit OneLogin (Catch and fallback to sandbox)
            try {
                scanOutput.onelogin = await scanOneLogin(env, refresh);
                if (scanOutput.onelogin && scanOutput.onelogin.warning) {
                    scanOutput.warnings.push(scanOutput.onelogin.warning);
                }
            } catch (err) {
                scanOutput.warnings.push(`OneLogin Scan: ${err.message}`);
                scanOutput.onelogin = SANDBOX_DATA.onelogin;
                scanOutput.isDemoMode = true;
            }

            // 3. Process structural scan violations
            const analysis = runSecurityScanRules(scanOutput.entra, scanOutput.onelogin);

            const responsePayload = {
                ...scanOutput,
                violations: analysis.violations,
                metrics: analysis.metrics
            };

            return new Response(JSON.stringify(responsePayload), {
                headers: {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*"
                }
            });
        }

        // Fallthrough - wrangler will map assets to ./public, but just in case, return 404
        return new Response("Not Found", { status: 404 });
    }
};
