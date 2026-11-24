/* ============================================================================
   VulnTrack — Realistic Seed Data Script (SQL Server 2019+)
   Seeds: 3 Roles, 3 Users, 8 Assets, 4 ImportBatches, 30 Vulnerabilities,
          VulnerabilityHistory, SlaRules, Alerts, AuditLogs, ReportRecords,
          and AppSettings.
   Anchor date: 2026-11-23 UTC
   ============================================================================ */

SET NOCOUNT ON;
GO

/* 1. Roles */
INSERT INTO dbo.AspNetRoles (Id, Name, NormalizedName, ConcurrencyStamp) VALUES
    (N'role-admin',   N'Administrator',    N'ADMINISTRATOR',    N'stamp-r1'),
    (N'role-analyst', N'Security Analyst', N'SECURITY ANALYST', N'stamp-r2'),
    (N'role-owner',   N'Asset Owner',      N'ASSET OWNER',      N'stamp-r3');
GO

/* 2. Users (1 per role; PasswordHash is a placeholder Identity v3 hash) */
INSERT INTO dbo.AspNetUsers
    (Id, UserName, NormalizedUserName, Email, NormalizedEmail, EmailConfirmed,
     PasswordHash, SecurityStamp, ConcurrencyStamp, FullName, Department, IsActive, LastLoginAt)
VALUES
    (N'usr-admin-01',   N'andrea.reyes@vulntrack.local',     N'ANDREA.REYES@VULNTRACK.LOCAL',
     N'andrea.reyes@vulntrack.local',     N'ANDREA.REYES@VULNTRACK.LOCAL',     1,
     N'AQAAAAIAAYagAAAAEDemoPlaceholderHashAdminOnlyReplaceViaUserManager==', N'sec-1', N'con-1',
     N'Andrea Reyes',     N'Security Office', 1, '2026-11-23T08:15:00'),
    (N'usr-analyst-01', N'marco.villanueva@vulntrack.local', N'MARCO.VILLANUEVA@VULNTRACK.LOCAL',
     N'marco.villanueva@vulntrack.local', N'MARCO.VILLANUEVA@VULNTRACK.LOCAL', 1,
     N'AQAAAAIAAYagAAAAEDemoPlaceholderHashAnalystOnlyReplaceViaUserManager==', N'sec-2', N'con-2',
     N'Marco Villanueva', N'SOC',             1, '2026-11-23T07:50:00'),
    (N'usr-owner-01',   N'joel.lim@vulntrack.local',         N'JOEL.LIM@VULNTRACK.LOCAL',
     N'joel.lim@vulntrack.local',         N'JOEL.LIM@VULNTRACK.LOCAL',         1,
     N'AQAAAAIAAYagAAAAEDemoPlaceholderHashOwnerOnlyReplaceViaUserManager==', N'sec-3', N'con-3',
     N'Joel Lim',         N'Radiology IT',    1, '2026-11-22T16:40:00');
GO

INSERT INTO dbo.AspNetUserRoles (UserId, RoleId) VALUES
    (N'usr-admin-01',   N'role-admin'),
    (N'usr-analyst-01', N'role-analyst'),
    (N'usr-owner-01',   N'role-owner');
GO

/* 3. SLA Rules (Critical=5->7d, High=4->14d, Medium=3->30d, Low=2->90d, Info=1->180d) */
INSERT INTO dbo.SlaRules (Severity, DueDays) VALUES
    (5, 7),
    (4, 14),
    (3, 30),
    (2, 90),
    (1, 180);
GO

/* 4. Assets (8 hosts; Criticality: 1=Low, 2=Medium, 3=High) */
SET IDENTITY_INSERT dbo.Assets ON;
INSERT INTO dbo.Assets
    (Id, Hostname, IpAddress, OperatingSystem, Department, Criticality, OwnerUserId, BusinessImpactNotes, IsActive, CreatedAt, LastScannedAt)
VALUES
    (1, N'vpn-gw-01',       N'10.20.0.4',    N'Ivanti Connect Secure 22.6', N'Network',      3, N'usr-owner-01', N'Primary remote-access VPN gateway for all staff.', 1, '2026-09-01T08:00:00', '2026-11-23T06:00:00'),
    (2, N'fw-edge-01',      N'10.20.0.1',    N'PAN-OS 11.1',                N'Network',      3, N'usr-owner-01', N'Perimeter firewall protecting internet ingress.',  1, '2026-09-01T08:00:00', '2026-11-23T06:00:00'),
    (3, N'srv-pacs-02',     N'10.40.12.20',  N'Windows Server 2022',        N'Radiology IT', 3, N'usr-owner-01', N'Diagnostic imaging PACS archive server.',          1, '2026-09-01T08:00:00', '2026-11-23T06:00:00'),
    (4, N'bastion-02',      N'10.20.2.12',   N'Ubuntu 24.04 LTS',           N'Network',      3, N'usr-admin-01', N'Privileged SSH jump host for production admins.',  1, '2026-09-01T08:00:00', '2026-11-23T06:00:00'),
    (5, N'mail-ex-01',      N'10.30.4.10',   N'Windows Server 2019',        N'Messaging',    3, N'usr-admin-01', N'Internal Exchange mailbox and relay host.',        1, '2026-09-01T08:00:00', '2026-11-23T06:00:00'),
    (6, N'web-portal-01',   N'10.50.1.18',   N'Debian 12',                  N'Web',          2, N'usr-analyst-01', N'Patient and partner self-service portal.',       1, '2026-09-01T08:00:00', '2026-11-23T06:00:00'),
    (7, N'build-runner-03', N'10.60.8.41',   N'Ubuntu 22.04 LTS',           N'DevOps',       2, N'usr-analyst-01', N'Internal CI/CD container build runner.',         1, '2026-09-01T08:00:00', '2026-11-23T06:00:00'),
    (8, N'WS-FIN-114',      N'10.70.19.114', N'Windows 11 Pro',             N'Finance IT',   1, N'usr-owner-01', N'Finance reconciliation corporate workstation.',    1, '2026-09-01T08:00:00', '2026-11-20T06:00:00');
SET IDENTITY_INSERT dbo.Assets OFF;
GO

/* 5. ImportBatches (4 batches; Source: 1=GreenboneApi, 2=ManualUpload) */
SET IDENTITY_INSERT dbo.ImportBatches ON;
INSERT INTO dbo.ImportBatches
    (Id, Source, FileName, TargetName, StartedAt, CompletedAt, Status, TotalFindings, NewCount, UpdatedCount, MarkedForVerificationCount, ReopenedCount, ErrorMessage, ImportedByUserId)
VALUES
    (1, 2, N'weekly-internal-2026-11-09.xml',      N'Weekly internal sweep', '2026-11-09T06:10:00', '2026-11-09T06:14:00', 2, 22, 16,  6, 0, 0, NULL, N'usr-analyst-01'),
    (2, 2, N'weekly-internal-2026-11-16.xml',      N'Weekly internal sweep', '2026-11-16T06:10:00', '2026-11-16T06:15:00', 3, 28,  9, 15, 3, 1, N'1 host had missing OS banner.', N'usr-analyst-01'),
    (3, 2, N'perimeter-vpn-rescan-2026-11-20.xml', N'Perimeter VPN rescan',  '2026-11-20T14:35:00', '2026-11-20T14:40:00', 2, 10,  1,  5, 4, 0, NULL, N'usr-analyst-01'),
    (4, 1, N'weekly-internal-2026-11-23.xml',      N'Weekly internal sweep', '2026-11-23T06:00:00', '2026-11-23T06:06:00', 2, 30,  4, 20, 5, 1, NULL, N'usr-admin-01');
SET IDENTITY_INSERT dbo.ImportBatches OFF;
GO

/* 6. Vulnerabilities (30 findings across all severities 1-5 and all statuses 1-5) */
SET IDENTITY_INSERT dbo.Vulnerabilities ON;
INSERT INTO dbo.Vulnerabilities
    (Id, CveId, Title, Description, Severity, CvssScore, AssetId, Port, Protocol, Service,
     BusinessImpact, RecommendedFix, OwnerUserId, DueDate, Status,
     DetectedAt, LastSeenAt, FixedAt, ClosedAt, CreatedByImportBatchId, LastImportBatchId, VerifiedByImportBatchId)
VALUES
    -- Core Critical findings
    (1,  N'CVE-2024-21887', N'Ivanti Connect Secure command injection', N'Authenticated command injection in web components.', 5, 9.1, 1, 443, N'tcp', N'https', N'Remote access gateway compromise.', N'Apply Ivanti 22.6R2.2+ patch.', N'usr-owner-01', '2026-11-30T00:00:00', 2, '2026-11-23T06:06:00', '2026-11-23T06:06:00', NULL, NULL, 4, 4, NULL),
    (2,  N'CVE-2024-3400',  N'PAN-OS GlobalProtect command injection', N'Unauthenticated root command injection via GlobalProtect.', 5, 10.0, 2, 443, N'tcp', N'https', N'Full perimeter firewall takeover.', N'Upgrade PAN-OS to 11.1.2-h3.', N'usr-owner-01', '2026-11-12T00:00:00', 1, '2026-11-05T06:14:00', '2026-11-23T06:06:00', NULL, NULL, 1, 4, NULL),
    (3,  N'CVE-2024-21413', N'Microsoft Outlook MonikerLink RCE', N'Protected View bypass via file:// moniker link.', 5, 9.8, 5, 443, N'tcp', N'ews', N'Corporate mail server compromise.', N'Install Feb 2024 Exchange/Office update.', N'usr-admin-01', '2026-11-14T00:00:00', 1, '2026-11-07T06:14:00', '2026-11-23T06:06:00', NULL, NULL, 1, 4, NULL),
    (4,  N'CVE-2024-3094',  N'xz-utils backdoor in liblzma', N'Supply-chain backdoor intercepting OpenSSH auth.', 5, 10.0, 7, 22, N'tcp', N'ssh', N'CI/CD runner compromise.', N'Downgrade xz-utils to 5.4.6 and rebuild.', N'usr-analyst-01', '2026-11-17T00:00:00', 4, '2026-11-10T06:14:00', '2026-11-16T06:15:00', '2026-11-17T15:00:00', '2026-11-20T14:40:00', 1, 2, 3),
    (5,  N'CVE-2024-1709',  N'ScreenConnect authentication bypass', N'Path traversal allows setup wizard re-execution.', 5, 10.0, 3, 8040, N'tcp', N'http', N'Radiology PACS unauthorized remote control.', N'Upgrade ScreenConnect to 23.9.8+.', N'usr-owner-01', '2026-11-18T00:00:00', 1, '2026-11-11T06:14:00', '2026-11-23T06:06:00', NULL, NULL, 1, 4, NULL),
    (6,  N'CVE-2024-4577',  N'PHP-CGI argument injection', N'Best-Fit encoding bypass allows remote code execution.', 5, 9.8, 6, 443, N'tcp', N'https', N'Public portal web shell risk.', N'Upgrade PHP to 8.3.8+.', N'usr-analyst-01', '2026-11-16T00:00:00', 1, '2026-11-09T06:14:00', '2026-11-23T06:06:00', NULL, NULL, 1, 4, NULL),
    (7,  N'CVE-2023-4966',  N'Citrix NetScaler session token leak', N'Sensitive buffer memory disclosure on gateway.', 5, 9.4, 1, 8443, N'tcp', N'https', N'Session hijacking bypassing MFA.', N'Apply vendor firmware update and kill sessions.', N'usr-owner-01', '2026-11-19T00:00:00', 3, '2026-11-12T06:14:00', '2026-11-20T14:40:00', '2026-11-21T14:15:00', NULL, 1, 3, NULL),
    (8,  N'CVE-2024-21762', N'FortiOS SSL VPN out-of-bounds write', N'Remote code execution via crafted HTTP requests.', 5, 9.6, 2, 10443, N'tcp', N'https', N'Perimeter VPN compromise.', N'Upgrade firewall firmware.', N'usr-owner-01', '2026-11-15T00:00:00', 2, '2026-11-08T06:14:00', '2026-11-23T06:06:00', NULL, NULL, 1, 4, NULL),
    -- High findings
    (9,  N'CVE-2024-6387',  N'OpenSSH regreSSHion race condition', N'Signal handler race condition in sshd.', 4, 8.1, 3, 22, N'tcp', N'ssh', N'Root code execution on PACS host.', N'Upgrade OpenSSH to 9.8p1+.', N'usr-owner-01', '2026-11-15T00:00:00', 1, '2026-11-01T06:14:00', '2026-11-23T06:06:00', NULL, NULL, 1, 4, NULL),
    (10, N'CVE-2023-44487', N'HTTP/2 rapid reset DoS', N'Stream cancellation flood exhausts server CPU.', 4, 7.5, 6, 443, N'tcp', N'https', N'Portal availability degradation.', N'Update nginx/HTTP2 stream limits.', N'usr-analyst-01', '2026-11-28T00:00:00', 2, '2026-11-14T06:15:00', '2026-11-23T06:06:00', NULL, NULL, 2, 4, NULL),
    (11, N'CVE-2024-21338', N'Windows kernel elevation of privilege', N'AppLocker driver IOCTL privilege escalation.', 4, 7.8, 3, 445, N'tcp', N'smb', N'Local privilege escalation to SYSTEM.', N'Apply Microsoft cumulative update.', N'usr-owner-01', '2026-11-20T00:00:00', 1, '2026-11-06T06:14:00', '2026-11-23T06:06:00', NULL, NULL, 1, 4, NULL),
    (12, N'CVE-2024-20353', N'Cisco ASA web services DoS', N'Unauthenticated reload via crafted HTTP request.', 4, 8.6, 2, 8443, N'tcp', N'https', N'Firewall availability interruption.', N'Patch ASA management plane.', N'usr-owner-01', '2026-11-25T00:00:00', 3, '2026-11-11T06:14:00', '2026-11-20T14:40:00', '2026-11-22T11:00:00', NULL, 1, 3, NULL),
    (13, N'CVE-2024-0519',  N'Chromium V8 out-of-bounds memory access', N'Heap corruption via crafted web content.', 4, 8.8, 8, 0, N'local', N'browser', N'Workstation endpoint compromise.', N'Update Chrome/Edge to latest stable.', N'usr-owner-01', '2026-11-29T00:00:00', 2, '2026-11-15T06:15:00', '2026-11-23T06:06:00', NULL, NULL, 2, 4, NULL),
    (14, N'CVE-2023-36884', N'Microsoft Office HTML RCE', N'Remote code execution via crafted Office document.', 4, 8.8, 8, 445, N'tcp', N'smb', N'Finance workstation compromise.', N'Apply Office security update.', N'usr-owner-01', '2026-11-19T00:00:00', 1, '2026-11-05T06:14:00', '2026-11-23T06:06:00', NULL, NULL, 1, 4, NULL),
    (15, N'CVE-2023-4863',  N'libwebp heap buffer overflow', N'Heap overflow decoding malformed WebP image.', 4, 8.8, 7, 8080, N'tcp', N'http', N'Build agent arbitrary code execution.', N'Update libwebp packages in base image.', N'usr-analyst-01', '2026-11-18T00:00:00', 4, '2026-11-04T06:14:00', '2026-11-16T06:15:00', '2026-11-16T18:00:00', '2026-11-23T06:06:00', 1, 2, 4),
    (16, N'CVE-2024-26169', N'Windows Error Reporting EoP', N'Privilege escalation in WER service.', 4, 7.8, 5, 445, N'tcp', N'smb', N'Mail server privilege escalation.', N'Install Windows Server cumulative patch.', N'usr-admin-01', '2026-11-30T00:00:00', 2, '2026-11-16T06:15:00', '2026-11-23T06:06:00', NULL, NULL, 2, 4, NULL),
    -- Medium findings
    (17, N'CVE-2023-48795', N'OpenSSH Terrapin prefix truncation', N'SSH handshake extension downgrade via MITM.', 3, 5.9, 4, 22, N'tcp', N'ssh', N'Weakened bastion SSH session integrity.', N'Upgrade OpenSSH to 9.6+ with strict kex.', N'usr-admin-01', '2026-12-02T00:00:00', 3, '2026-11-02T06:14:00', '2026-11-20T14:40:00', '2026-11-22T16:45:00', NULL, 1, 3, NULL),
    (18, N'CVE-2023-5678',  N'OpenSSL excessive DH key generation time', N'CPU exhaustion processing large DH parameters.', 3, 5.3, 6, 8443, N'tcp', N'https', N'Portal TLS handshake latency.', N'Update OpenSSL to 3.0.13+.', N'usr-analyst-01', '2026-12-10T00:00:00', 1, '2026-11-10T06:14:00', '2026-11-23T06:06:00', NULL, NULL, 1, 4, NULL),
    (19, N'CVE-2022-0778',  N'OpenSSL BN_mod_sqrt infinite loop', N'Malformed certificate triggers infinite loop.', 3, 6.5, 4, 443, N'tcp', N'https', N'Bastion management UI DoS.', N'Update OpenSSL package.', N'usr-admin-01', '2026-12-12T00:00:00', 4, '2026-11-09T06:14:00', '2026-11-16T06:15:00', '2026-11-18T10:00:00', '2026-11-23T06:06:00', 1, 2, 4),
    (20, N'CVE-2023-38546', N'curl cookie injection with none file', N'Arbitrary cookie injection under specific API use.', 3, 4.8, 7, 443, N'tcp', N'https', N'Low-impact build script manipulation.', N'Upgrade libcurl to 8.4.0+.', N'usr-analyst-01', '2026-12-16T00:00:00', 2, '2026-11-16T06:15:00', '2026-11-23T06:06:00', NULL, NULL, 2, 4, NULL),
    (21, N'CVE-2023-4911',  N'glibc Looney Tunables buffer overflow', N'Local privilege escalation via GLIBC_TUNABLES.', 3, 6.8, 4, 22, N'tcp', N'ssh', N'Local root escalation on bastion.', N'Patch glibc package.', N'usr-admin-01', '2026-12-09T00:00:00', 3, '2026-11-09T06:14:00', '2026-11-20T14:40:00', '2026-11-21T09:00:00', NULL, 1, 3, NULL),
    (22, N'CVE-2024-27316', N'Apache HTTP Server CONTINUATION flood', N'Memory exhaustion via HTTP/2 CONTINUATION frames.', 3, 6.5, 6, 80, N'tcp', N'http', N'Web portal memory exhaustion.', N'Upgrade httpd to 2.4.59+.', N'usr-analyst-01', '2026-12-20T00:00:00', 1, '2026-11-20T14:40:00', '2026-11-23T06:06:00', NULL, NULL, 3, 4, NULL),
    -- Low findings
    (23, N'CVE-2023-51385', N'OpenSSH OS command injection via username', N'Shell metacharacters in ProxyCommand expansion.', 2, 3.7, 4, 2222, N'tcp', N'ssh', N'Minimal exposure due to restricted users.', N'Upgrade OpenSSH client/server.', N'usr-admin-01', '2027-02-07T00:00:00', 1, '2026-11-09T06:14:00', '2026-11-23T06:06:00', NULL, NULL, 1, 4, NULL),
    (24, N'CVE-2023-29491', N'ncurses local privilege escalation', N'Terminfo database parsing flaw in setuid binaries.', 2, 3.3, 7, 0, N'local', N'os', N'Limited to local shell users.', N'Apply Ubuntu ncurses security update.', N'usr-analyst-01', '2027-02-14T00:00:00', 4, '2026-11-09T06:14:00', '2026-11-16T06:15:00', '2026-11-17T11:00:00', '2026-11-23T06:06:00', 1, 2, 4),
    (25, N'CVE-2022-40674', N'libexpat heap use-after-free', N'XML parser memory corruption.', 2, 3.9, 5, 80, N'tcp', N'http', N'Internal service only.', N'Update libexpat dependency.', N'usr-admin-01', '2027-02-14T00:00:00', 5, '2026-11-16T06:15:00', '2026-11-23T06:06:00', NULL, NULL, 2, 4, NULL),
    (26, N'CVE-2023-2650',  N'OpenSSL OBJ_obj2txt processing delay', N'Long ASN.1 OID parsing slowdown.', 2, 3.5, 1, 80, N'tcp', N'http', N'Negligible impact on internal monitor port.', N'Apply next scheduled firmware release.', N'usr-owner-01', '2027-02-21T00:00:00', 1, '2026-11-23T06:06:00', '2026-11-23T06:06:00', NULL, NULL, 4, 4, NULL),
    (27, N'CVE-2021-41617', N'OpenSSH AuthorizedKeysCommand supplemental groups', N'Privilege drop oversight when custom command used.', 2, 3.1, 3, 2222, N'tcp', N'ssh', N'Non-default config not active.', N'Accept risk or upgrade OpenSSH.', N'usr-owner-01', '2027-02-14T00:00:00', 5, '2026-11-16T06:15:00', '2026-11-23T06:06:00', NULL, NULL, 2, 4, NULL),
    -- Info findings
    (28, N'NVT-TLS-EXP-01', N'TLS certificate expires within 30 days', N'Leaf TLS certificate approaching renewal window.', 1, 0.0, 6, 8443, N'tcp', N'https', N'Service outage if certificate expires.', N'Renew TLS certificate via internal CA.', N'usr-analyst-01', '2027-05-22T00:00:00', 1, '2026-11-23T06:06:00', '2026-11-23T06:06:00', NULL, NULL, 4, 4, NULL),
    (29, N'NVT-SSH-BAN-01', N'SSH server version banner disclosed', N'OpenSSH banner exposes minor patch level.', 1, 0.0, 4, 2200, N'tcp', N'ssh', N'Informational reconnaissance detail.', N'No action required; documented baseline.', N'usr-admin-01', '2027-05-15T00:00:00', 3, '2026-11-16T06:15:00', '2026-11-20T14:40:00', '2026-11-22T09:00:00', NULL, 2, 3, NULL),
    (30, N'NVT-ICMP-TS-01', N'ICMP timestamp reply enabled', N'Host responds to ICMP type 13 timestamp requests.', 1, 0.0, 8, 0, N'icmp', N'icmp', N'Informational clock disclosure.', N'Block ICMP type 13/14 in workstation firewall.', N'usr-owner-01', '2027-05-22T00:00:00', 1, '2026-11-23T06:06:00', '2026-11-23T06:06:00', NULL, NULL, 4, 4, NULL);
SET IDENTITY_INSERT dbo.Vulnerabilities OFF;
GO

/* 7. VulnerabilityHistory (lifecycle trail including RescanVerified, Reopened, Closed) */
INSERT INTO dbo.VulnerabilityHistory
    (VulnerabilityId, ChangeType, OldValue, NewValue, Note, ChangedByUserId, ImportBatchId, ChangedAt)
VALUES
    (1,  1, NULL, N'Open', N'Imported from weekly-internal-2026-11-23.xml', NULL, 4, '2026-11-23T06:06:00'),
    (1,  2, NULL, N'Critical (9.1)', N'Ranked P1 against Critical asset vpn-gw-01', NULL, 4, '2026-11-23T06:06:10'),
    (1,  3, NULL, N'Joel Lim', N'Auto-assigned from asset registry', N'usr-analyst-01', 4, '2026-11-23T06:15:00'),
    (1,  5, N'Open', N'InProgress', N'Maintenance window booked for patch rollout', N'usr-owner-01', NULL, '2026-11-23T09:00:00'),
    (4,  1, NULL, N'Open', N'Imported from weekly-internal-2026-11-09.xml', NULL, 1, '2026-11-09T06:14:00'),
    (4,  5, N'Open', N'FixedAwaitingVerification', N'xz-utils downgraded and runner rebuilt', N'usr-analyst-01', NULL, '2026-11-17T15:00:00'),
    (4,  7, N'FixedAwaitingVerification', N'Verified', N'Absent from rescan batch #3', NULL, 3, '2026-11-20T14:40:00'),
    (4,  8, N'FixedAwaitingVerification', N'Closed', N'Closed with rescan batch #3 evidence', N'usr-analyst-01', 3, '2026-11-20T14:40:05'),
    (7,  5, N'InProgress', N'FixedAwaitingVerification', N'Vendor firmware applied; waiting for rescan', N'usr-owner-01', NULL, '2026-11-21T14:15:00'),
    (8,  6, N'FixedAwaitingVerification', N'InProgress', N'Still detected in weekly-internal-2026-11-23.xml; reopened', NULL, 4, '2026-11-23T06:06:00'),
    (17, 5, N'Open', N'FixedAwaitingVerification', N'OpenSSH upgraded; awaiting rescan verification', N'usr-admin-01', NULL, '2026-11-22T16:45:00');
GO

/* 8. Alerts (Type: 1=CriticalFinding, 2=SlaOverdue, 3=RescanResult, 4=ImportFailed) */
INSERT INTO dbo.Alerts ([Type], Message, VulnerabilityId, RecipientUserId, IsRead, CreatedAt) VALUES
    (2, N'SLA breach: CVE-2024-3400 on fw-edge-01 is 11 days overdue.', 2, N'usr-admin-01', 0, '2026-11-23T06:20:00'),
    (2, N'SLA breach: CVE-2024-21413 on mail-ex-01 is 9 days overdue.', 3, N'usr-admin-01', 0, '2026-11-23T06:20:00'),
    (1, N'Critical finding imported: CVE-2024-21887 on vpn-gw-01.', 1, N'usr-owner-01', 0, '2026-11-23T06:12:00'),
    (3, N'Rescan verified closure of CVE-2024-3094 on build-runner-03.', 4, N'usr-analyst-01', 1, '2026-11-20T14:45:00'),
    (4, N'Import warning: 1 host missing OS banner in weekly-internal-2026-11-16.xml.', NULL, N'usr-analyst-01', 1, '2026-11-16T06:16:00');
GO

/* 9. AuditLogs (Append-Only) */
INSERT INTO dbo.AuditLogs (UserId, Action, TargetType, TargetId, Details, IpAddress, [Timestamp]) VALUES
    (N'usr-admin-01',   N'ImportCompleted', N'ImportBatch',   N'4',  N'weekly-internal-2026-11-23.xml: 4 new, 20 updated, 5 awaiting verification, 1 reopened', N'10.20.1.12', '2026-11-23T06:06:00'),
    (N'usr-owner-01',   N'StatusChanged',   N'Vulnerability', N'1',  N'Changed CVE-2024-21887 from Open to InProgress', N'10.40.12.5', '2026-11-23T09:00:00'),
    (N'usr-analyst-01', N'FindingClosed',   N'Vulnerability', N'4',  N'Closed CVE-2024-3094 after rescan batch #3 verification', N'10.20.1.44', '2026-11-20T14:40:05');
GO

/* 10. ReportRecords (Format: 1=PDF, 2=CSV) */
INSERT INTO dbo.ReportRecords (Name, [Type], Format, FiltersJson, CreatedByUserId, CreatedAt, FilePath) VALUES
    (N'Executive Security Summary - Nov 2026', N'Executive summary', 1, N'{"dateFrom":"2026-11-01","dateTo":"2026-11-23"}', N'usr-admin-01', '2026-11-23T07:30:00', N'/reports/exec-2026-11.pdf'),
    (N'Overdue SLA Escalation List',           N'Overdue remediation', 2, N'{"overdueOnly":true}', N'usr-analyst-01', '2026-11-22T16:10:00', N'/reports/overdue-2026-11-22.csv');
GO

/* 11. AppSettings (Secrets encrypted via Data Protection / Key Vault reference) */
INSERT INTO dbo.AppSettings ([Key], [Value], IsEncrypted, Description, UpdatedByUserId, UpdatedAt) VALUES
    (N'Greenbone:Host',               N'gvm-scanner.internal.local', 0, N'Authorized Greenbone GMP hostname', N'usr-admin-01', '2026-11-10T08:30:00'),
    (N'Greenbone:Port',               N'9390',                       0, N'Greenbone GMP TLS port',            N'usr-admin-01', '2026-11-10T08:30:00'),
    (N'Greenbone:Username',           N'vulntrack-gmp',              0, N'Greenbone service account',         N'usr-admin-01', '2026-11-10T08:30:00'),
    (N'Greenbone:EncryptedPassword',  N'kv://vulntrack-secrets/greenbone-gmp-password', 1, N'Encrypted secret or Key Vault URI; never plaintext', N'usr-admin-01', '2026-11-10T08:30:00'),
    (N'Import:NightlyScheduleUtc',    N'02:00',                      0, N'Nightly rescan and sync schedule (UTC)', N'usr-admin-01', '2026-11-10T08:30:00'),
    (N'Import:AutoAssignOwners',      N'true',                       0, N'Assign owners from Assets registry on import', N'usr-admin-01', '2026-11-10T08:30:00'),
    (N'Notifications:EmailEnabled',   N'true',                       0, N'Enable outbound email alerts',      N'usr-admin-01', '2026-11-10T08:30:00'),
    (N'Notifications:Recipients',     N'soc@vulntrack.local,andrea.reyes@vulntrack.local', 0, N'Default notification recipients', N'usr-admin-01', '2026-11-10T08:30:00');
GO
