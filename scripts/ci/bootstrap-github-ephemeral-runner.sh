#!/usr/bin/env bash
# TuranSec EDR GitHub Actions -- one-job ephemeral QA runner.
# Execute on a NEW disposable isolated Linux x86-64 VM with Docker installed.
# Must run inside the official verified actions-runner directory.
set -Eeuo pipefail

if [[ "$EDR_QA_DISPOSABLE_VM" != "yes" ]]; then
  echo 'Refusing: acknowledge a separate disposable CI VM with EDR_QA_DISPOSABLE_VM=yes' >&2
  exit 2
fi
if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo 'Requires a disposable Linux x86-64 host' >&2
  exit 2
fi
if [[ "$(id -u)" == "0" ]]; then
  echo 'Do not execute the GitHub Actions runner as root' >&2
  exit 2
fi
if [[ ! -x ./config.sh || ! -x ./run.sh ]]; then
  echo 'First download and SHA256-verify the official GitHub actions/runner release into this directory' >&2
  exit 2
fi
if ! command -v docker >/dev/null || ! docker info >/dev/null 2>&1; then
  echo 'Docker Engine must be installed and available on the isolated CI VM' >&2
  exit 2
fi

# The short-lived repo registration token is obtained LOCALLY from:
# GitHub repository Settings > Actions > Runners > New self-hosted runner.
# Do not enter or store the token in ChatGPT, GitHub issues, or source files.
if [[ -z "$GH_RUNNER_REGISTRATION_TOKEN" ]]; then
  if [[ ! -t 0 ]]; then
    echo 'Require local interactive input or GH_RUNNER_REGISTRATION_TOKEN' >&2
    exit 2
  fi
  read -r -s -p 'Paste the short-lived GitHub runner registration token locally: ' GH_RUNNER_REGISTRATION_TOKEN
  printf '\n'
fi
if [[ -z "$GH_RUNNER_REGISTRATION_TOKEN" ]]; then
  echo 'An empty runner registration token is invalid' >&2
  exit 2
fi

name="turansec-edr-qa-$(hostname -s)-$$"
./config.sh --unattended --ephemeral \
  --url https://github.com/suhaylx/EDR \
  --token "$GH_RUNNER_REGISTRATION_TOKEN" \
  --labels turansec-edr-qa \
  --name "$name" \
  --work _work
unset GH_RUNNER_REGISTRATION_TOKEN

echo 'Ephemeral runner registered. Accepts one matching trusted GitHub Actions job.'
echo 'After one job, it auto-deregisters; delete the disposable VM.'
exec ./run.sh
