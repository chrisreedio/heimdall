# Security policy

## Reporting a vulnerability

Please report vulnerabilities in Heimdall privately, using **GitHub's private vulnerability reporting** on this repository, or by email to the maintainer. Don't open a public issue. Include steps to reproduce and the affected version. You'll get an acknowledgement within a few days.

## Scope

In scope: the hub (`heimdall`), the collectors (`collect.sh`, `collect.ps1`), the systemd units and the release process.

The design goal is that **a fully compromised hub can't touch your servers**:
- The hub never connects to them, holds no credentials for them, and never serves code to them.
- The collector ignores everything the hub sends back.

Anything that breaks that is a high-severity issue. See the threat model in the [README](README.md#security-first).

## Supported versions

Only the latest release gets fixes before 1.0.

## Status of the security review

Heimdall has had internal review, plus extensive negative testing (strict decoding, CSRF/Origin, scope isolation, token handling, signature validation). It has **not yet had an independent external security review**. That review is a 1.0 requirement.
