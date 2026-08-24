#!/bin/bash
# GUARDRAIL IDENTITY MFA SECURITY DASHBOARD DEPLOYMENT UTILITY

# Exit on error
set -e

echo "🚀 Beginning deployment pipeline..."

# 1. Initialize Git Repository
if [ ! -d ".git" ]; then
    echo "📦 Initializing local Git repository..."
    git init
    # Configure user name/email if missing to prevent commit errors
    if [ -z "$(git config user.name)" ]; then
        git config user.name "gwalejewski"
    fi
    if [ -z "$(git config user.email)" ]; then
        git config user.email "gwalejewski@gmail.com"
    fi
else
    echo "✓ Git repository already initialized."
fi

# 2. Add and Commit Files
echo "📝 Committing project changes..."
git add -A
git commit -m "Migrate dashboard to Cloudflare Workers with Entra & OneLogin integration" || echo "No changes to commit"

# 3. Configure Remote and Push to GitHub
echo "🔗 Setting up GitHub remote connection..."
REMOTE_URL="git@github.com:gwalejewski/identity-security-dashboard.git"

if git remote | grep -q "origin"; then
    git remote set-url origin "$REMOTE_URL"
else
    git remote add origin "$REMOTE_URL"
fi

echo "📤 Pushing code to GitHub (main branch)..."
# We wrap push in a try/catch, since the repository must be created on GitHub first
if git push -u origin main; then
    echo "✓ Code successfully uploaded to GitHub!"
else
    echo "⚠️ Git push failed. Please verify that you have created a blank repository named 'identity-security-dashboard' in your GitHub account (github.com/gwalejewski/identity-security-dashboard) and try again."
fi

# 4. Deploy to Cloudflare Workers
echo "☁️ Deploying Worker to Cloudflare..."
npx wrangler deploy

echo "🎉 Deployment Pipeline Complete!"
