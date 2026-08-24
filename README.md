# GuardRail: Identity MFA Security Audit Dashboard

A premium, interactive, zero-dependency HTML5/CSS3/JavaScript dashboard designed to analyze Microsoft Entra ID and OneLogin tenant configurations for MFA bypass risks, disabled policies, and vulnerable user profiles.

## Features

- **Interactive Security Scoring**: Calculates real-time risk index based on Conditional Access violations.
- **Unified Risk Matrix**: Visually breaks down vulnerabilities (policy exclusions, weak factors, legacy auth, unenrolled admin accounts).
- **Entra ID & OneLogin Auditing**: Separate, drill-down check suites tracking active policies, directory roles, tenant configurations, and factor assignments.
- **Interactive Remediation Pathways**: Step-by-step guides containing manual portal navigation steps and ready-to-run CLI commands (Graph PowerShell and OneLogin REST API `curl` commands).
- **Secure Local Import**: Collector scripts capture configuration states locally so that tenant secrets are never exposed to the web browser.

---

## Getting Started

### 1. Open the Dashboard in Your Browser
Simply double-click the [index.html](file:///Users/gwalejew/.gemini/antigravity/scratch/identity-security-dashboard/index.html) file to launch the dashboard locally in your default web browser (Chrome, Safari, Firefox). 

### 2. Configure Your Active Workspace
We recommend opening this directory as your active workspace in your IDE to browse the files and inspect the scan rules.
- **Workspace Directory**: `/Users/gwalejew/.gemini/antigravity/scratch/identity-security-dashboard`

### 3. Extracting and Importing Real Configurations
To audit your own environments, go to the **Data Integration** tab in the dashboard, copy the collector script for your IDP, and run it locally.
- **Microsoft Entra ID**: Run the PowerShell script to query and export policies and user states to `entra_mfa_audit.json`.
- **OneLogin**: Run the Python script to query policies and users to `onelogin_mfa_audit.json`.
- **Import**: Click the **Import Config JSON** button in the top right of the dashboard and upload the generated JSON file to see your live audit score.

---

## File Structure

- [index.html](file:///Users/gwalejew/.gemini/antigravity/scratch/identity-security-dashboard/index.html) - Structural markup and semantic HTML skeleton.
- [styles.css](file:///Users/gwalejew/.gemini/antigravity/scratch/identity-security-dashboard/styles.css) - Modern, responsive glassmorphic dark-theme design system.
- [app.js](file:///Users/gwalejew/.gemini/antigravity/scratch/identity-security-dashboard/app.js) - Rules scanner engine, state management, and DOM event listeners.
