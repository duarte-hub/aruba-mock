#!/usr/bin/env bash
# Publish this folder to GitHub.
#
# Two paths:
#   1. With the GitHub CLI (`gh`) installed and authenticated -> creates the repo for you.
#   2. With plain `git` only -> you create the empty repo on github.com first, paste its URL.
#
# Usage:
#   ./scripts/publish-to-github.sh             # interactive
#   ./scripts/publish-to-github.sh aruba-mock  # repo name
set -euo pipefail

cd "$(dirname "$0")/.."

REPO_NAME="${1:-aruba-mock}"
DEFAULT_BRANCH="main"

if [[ ! -d .git ]]; then
    echo "==> Initializing git repository"
    git init -b "$DEFAULT_BRANCH"
fi

# Make sure user.name / user.email are set
if [[ -z "$(git config user.name || true)" ]]; then
    read -rp "Git user.name (e.g. Duarte Da): " NAME
    git config user.name "$NAME"
fi
if [[ -z "$(git config user.email || true)" ]]; then
    read -rp "Git user.email: " EMAIL
    git config user.email "$EMAIL"
fi

echo "==> Staging files"
git add -A

if git diff --cached --quiet; then
    echo "Nothing to commit."
else
    git commit -m "Initial commit: Aruba Mock dashboard"
fi

if command -v gh >/dev/null 2>&1; then
    echo "==> Creating remote with gh"
    if ! gh auth status >/dev/null 2>&1; then
        gh auth login
    fi

    read -rp "Visibility [private/public] (default private): " VIS
    VIS="${VIS:-private}"

    # Idempotent: only create if it doesn't exist
    if gh repo view "$REPO_NAME" >/dev/null 2>&1; then
        echo "Repo $REPO_NAME already exists, skipping create."
        OWNER=$(gh api user --jq .login)
        git remote add origin "git@github.com:${OWNER}/${REPO_NAME}.git" 2>/dev/null || \
            git remote set-url origin "git@github.com:${OWNER}/${REPO_NAME}.git"
    else
        gh repo create "$REPO_NAME" --"$VIS" --source=. --remote=origin --push
        exit 0
    fi
else
    echo "==> 'gh' not found. Falling back to plain git."
    echo "    1. Go to https://github.com/new and create an empty repo named '$REPO_NAME'"
    echo "       (no README, no .gitignore, no license — they'd conflict)."
    read -rp "Paste the SSH or HTTPS URL of the new empty repo: " URL
    git remote add origin "$URL" 2>/dev/null || git remote set-url origin "$URL"
fi

echo "==> Pushing to origin/$DEFAULT_BRANCH"
git push -u origin "$DEFAULT_BRANCH"
echo "Done."
