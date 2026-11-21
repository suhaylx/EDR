# TuranSec EDR development lab provisioning

Status: planning and lab preparation as of 2026-11-21. These are starting estimates, not measured production capacity.

## Recommended isolated lab

| Hostname | OS | vCPU | RAM | SSD/NVMe | Role |
| --- | --- | ---: | ---: | ---: | --- |
| EDR-APP-01 | Ubuntu Server 24.04 LTS | 8 | 32 GiB | 300 GiB | Go API, PostgreSQL, dashboard, queue, build/staging |
| EDR-DATA-01 | Ubuntu Server 24.04 LTS | 8 | 32 GiB | 1 TiB NVMe | ClickHouse event storage, investigations, retention tests |
| AD-DC-01 | Windows Server 2022 or 2025 | 4 | 8 GiB | 100 GiB | Test AD DS, LDAPS certificate, GPO, internal DNS |
| WIN-TEST-01 | Windows 11 64-bit | 4 | 8 GiB | 100 GiB | Test agent, Sysmon and DLL file/load telemetry |
| WIN-TEST-02 | Windows 11 64-bit | 4 | 8 GiB | 100 GiB | Domain-joined GPO deployment, canary and uninstall controls |
| LINUX-TEST-01 | Ubuntu Server 24.04 LTS | 4 | 8 GiB | 100 GiB | Linux agent, ClamAV and Linux Sysmon compatibility |

Suggested single virtualization host: 32 CPU threads, 128 GiB RAM, at least 2 TiB usable NVMe, plus separate backup storage. Hypervisors: Proxmox, Hyper-V or VMware. One host is not high availability.

A cheaper proof of concept can omit EDR-DATA-01 and colocate telemetry and PostgreSQL on EDR-APP-01. This is not suitable for scale/load tests. Add one Rocky Linux or RHEL-family endpoint VM when validating RPM-based packaging. Consider a Windows Server member machine to verify server-specific exclusions and compatibility.

## Network and security baseline

- Separate test VLAN; no test DC or management console exposed to the public Internet.
- Stable DNS/FQDN for EDR-APP-01 and AD-DC-01; reliable internal NTP and certificate trust.
- Agents -> EDR-APP-01: HTTPS/mTLS on TCP 443 when implemented. The existing localhost-only development API on port 8080 must NOT be publicly exposed.
- Authorized directory connector -> AD-DC-01: LDAPS on TCP 636, or 3269 when global catalog TLS is necessary; validate hostname and CA chain.
- Internal AD/GPO services require Microsoft-recommended domain ports; keep SMB 445 and RPC scoped to the lab/admin network. No blanket WAN exposure.
- SSH 22 and remote management only from a dedicated admin VLAN; role-based access and audit.
- Snapshot VMs before EDR agent and Sysmon install/upgrade/configuration tests; maintain backup and recovery procedures.
- Use synthetic security fixtures and EICAR for AV integration testing; do not detonate live malware on ordinary production-style hosts.
- Store secrets in a vault, not in GitHub/chat or an environment file committed to the repository. Generate PKI for test mTLS and LDAPS.

## Architecture and rollout gates

Agent 1 / InfoSec: review endpoint trust bootstrap, certificate lifecycle, tenant isolation, Sysmon collection safety, ClamAV updates and minimum tamper-protection claims. Approve security gates before exposing an API outside an isolated lab.

Agent 2 / Backend and Deployment: provision lab infrastructure, build/sign packages, implement mTLS enrollment, PostgreSQL migrations, event queue, observability, Sysmon canary policy deployment and rollback. Own AD/LDAPS discovery and authorized GPO deployment orchestration.

Agent 3 / QA: run Go API tests, adversarial authorization and replay checks, real Windows/Linux agent/service tests, Sysmon rollback and uninterrupted scanning tests. Block release on missing evidence.

Agent 4 / PM: maintain issue priorities, accountable owners, testable acceptance gates, and verified build/release evidence. Do not claim a deployment based on a plan.

## Production pilot sizing placeholder, NOT a quote or capacity guarantee

For a first non-HA pilot on roughly 50-100 low-to-moderate-event endpoints, consider separating Go API and queue (8 vCPU/16-32 GiB), PostgreSQL (4-8 vCPU/16-32 GiB plus reliable backup storage), and ClickHouse (8-16 vCPU/32-64 GiB with 1-2 TiB fast NVMe), then measure actual events per second, event sizes, 30-90 day retention, queries and storage compression. Retention and selected Windows Sysmon Event 7 collection can change capacity by orders of magnitude. High availability, tenants, production SLOs and retention need distinct capacity and replication design.

## Owner checklist

- [ ] Choose lab site/hypervisor (Proxmox, Hyper-V, VMware, cloud or existing VMs)
- [ ] Confirm number of initial endpoints and desired telemetry retention
- [ ] Provision isolated Ubuntu app/data VMs and 2 Windows test VMs
- [ ] Provide test-only Windows Server domain, PKI and LDAPS access
- [ ] Specify Linux distro/kernel and Windows workstation/server versions
- [ ] Set internal DNS/FQDN, CA, outbound update policy, firewall and backup access
- [ ] Create an authorized **private** GitHub repository `turansec-edr`; do not submit GitHub passwords or tokens in chat
- [ ] Decide whether any environment is air-gapped/offline

External references: https://docs.clamav.net/ ; https://github.com/microsoft/SysmonForLinux ; https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/configure-ldap-signing-certificates ; https://clickhouse.com/docs
