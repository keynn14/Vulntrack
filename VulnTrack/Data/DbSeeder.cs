using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using VulnTrack.Data.Entities;
using VulnTrack.Models;

namespace VulnTrack.Data;

public static class DbSeeder
{
    public static async Task SeedAsync(IServiceProvider services)
    {
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

        await db.Database.MigrateAsync();

        // 1. Seed Roles
        string[] roleNames = { Roles.Administrator, Roles.SecurityAnalyst, Roles.AssetOwner };
        foreach (var roleName in roleNames)
        {
            if (!await roleManager.RoleExistsAsync(roleName))
            {
                await roleManager.CreateAsync(new IdentityRole(roleName));
            }
        }

        // 2. Seed one real Identity user per role with valid password hashes
        var admin = await EnsureUserAsync(userManager, "andrea.reyes@vulntrack.local", "Admin@1234", "Andrea Reyes", "Security Office", Roles.Administrator);
        var analyst = await EnsureUserAsync(userManager, "marco.villanueva@vulntrack.local", "Analyst@1234", "Marco Villanueva", "SOC", Roles.SecurityAnalyst);
        var owner = await EnsureUserAsync(userManager, "joel.lim@vulntrack.local", "Owner@1234", "Joel Lim", "Radiology IT", Roles.AssetOwner);

        // 3. Seed SLA Rules
        if (!await db.SlaRules.AnyAsync())
        {
            db.SlaRules.AddRange(
                new SlaRuleEntity { Severity = VulnerabilitySeverity.Critical, DueDays = 7 },
                new SlaRuleEntity { Severity = VulnerabilitySeverity.High, DueDays = 14 },
                new SlaRuleEntity { Severity = VulnerabilitySeverity.Medium, DueDays = 30 },
                new SlaRuleEntity { Severity = VulnerabilitySeverity.Low, DueDays = 90 },
                new SlaRuleEntity { Severity = VulnerabilitySeverity.Info, DueDays = 180 }
            );
            await db.SaveChangesAsync();
        }

        // 4. Seed AppSettings
        if (!await db.AppSettings.AnyAsync())
        {
            db.AppSettings.AddRange(
                new AppSettingEntity { Key = "Greenbone:Host", Value = "gvm-scanner.internal.local", Description = "Authorized Greenbone GMP hostname", UpdatedByUserId = admin.Id },
                new AppSettingEntity { Key = "Greenbone:Port", Value = "9390", Description = "Greenbone GMP TLS port", UpdatedByUserId = admin.Id },
                new AppSettingEntity { Key = "Greenbone:Username", Value = "vulntrack-gmp", Description = "Greenbone service account", UpdatedByUserId = admin.Id },
                new AppSettingEntity { Key = "Greenbone:EncryptedPassword", Value = "kv://vulntrack-secrets/greenbone-gmp-password", IsEncrypted = true, Description = "Secret reference (never plaintext)", UpdatedByUserId = admin.Id },
                new AppSettingEntity { Key = "Import:NightlyScheduleUtc", Value = "02:00", Description = "Nightly rescan schedule (UTC)", UpdatedByUserId = admin.Id },
                new AppSettingEntity { Key = "Import:AutoAssignOwners", Value = "true", Description = "Auto-assign owners from Assets registry", UpdatedByUserId = admin.Id },
                new AppSettingEntity { Key = "Notifications:EmailEnabled", Value = "true", Description = "Enable outbound email alerts", UpdatedByUserId = admin.Id },
                new AppSettingEntity { Key = "Notifications:Recipients", Value = "soc@vulntrack.local,andrea.reyes@vulntrack.local", Description = "Default notification recipients", UpdatedByUserId = admin.Id }
            );
            await db.SaveChangesAsync();
        }

        // 5. Seed Assets, ImportBatches, Vulnerabilities, History, Alerts, AuditLogs, Reports
        if (await db.Assets.AnyAsync()) return;

        var now = DateTime.UtcNow;
        var assets = new List<AssetEntity>
        {
            new() { Hostname = "vpn-gw-01", IpAddress = "10.20.0.4", OperatingSystem = "Ivanti Connect Secure 22.6", Department = "Network", Criticality = AssetCriticality.High, OwnerUserId = owner.Id, BusinessImpactNotes = "Primary remote-access VPN gateway for all staff.", LastScannedAt = now.AddHours(-4) },
            new() { Hostname = "fw-edge-01", IpAddress = "10.20.0.1", OperatingSystem = "PAN-OS 11.1", Department = "Network", Criticality = AssetCriticality.High, OwnerUserId = owner.Id, BusinessImpactNotes = "Perimeter firewall protecting internet ingress.", LastScannedAt = now.AddHours(-4) },
            new() { Hostname = "srv-pacs-02", IpAddress = "10.40.12.20", OperatingSystem = "Windows Server 2022", Department = "Radiology IT", Criticality = AssetCriticality.High, OwnerUserId = owner.Id, BusinessImpactNotes = "Diagnostic imaging PACS archive server.", LastScannedAt = now.AddHours(-4) },
            new() { Hostname = "bastion-02", IpAddress = "10.20.2.12", OperatingSystem = "Ubuntu 24.04 LTS", Department = "Network", Criticality = AssetCriticality.High, OwnerUserId = admin.Id, BusinessImpactNotes = "Privileged SSH jump host for production admins.", LastScannedAt = now.AddHours(-4) },
            new() { Hostname = "mail-ex-01", IpAddress = "10.30.4.10", OperatingSystem = "Windows Server 2019", Department = "Messaging", Criticality = AssetCriticality.High, OwnerUserId = admin.Id, BusinessImpactNotes = "Internal Exchange mailbox and relay host.", LastScannedAt = now.AddHours(-4) },
            new() { Hostname = "web-portal-01", IpAddress = "10.50.1.18", OperatingSystem = "Debian 12", Department = "Web", Criticality = AssetCriticality.Medium, OwnerUserId = analyst.Id, BusinessImpactNotes = "Patient and partner self-service portal.", LastScannedAt = now.AddHours(-4) },
            new() { Hostname = "build-runner-03", IpAddress = "10.60.8.41", OperatingSystem = "Ubuntu 22.04 LTS", Department = "DevOps", Criticality = AssetCriticality.Medium, OwnerUserId = analyst.Id, BusinessImpactNotes = "Internal CI/CD container build runner.", LastScannedAt = now.AddHours(-4) },
            new() { Hostname = "WS-FIN-114", IpAddress = "10.70.19.114", OperatingSystem = "Windows 11 Pro", Department = "Finance IT", Criticality = AssetCriticality.Low, OwnerUserId = owner.Id, BusinessImpactNotes = "Finance reconciliation corporate workstation.", LastScannedAt = now.AddDays(-3) }
        };
        db.Assets.AddRange(assets);
        await db.SaveChangesAsync();

        var b1 = new ImportBatchEntity { Source = ImportSource.ManualUpload, FileName = "weekly-internal-2026-11-09.xml", TargetName = "Weekly internal sweep", StartedAt = now.AddDays(-14), CompletedAt = now.AddDays(-14).AddMinutes(4), Status = ImportStatus.Completed, TotalFindings = 22, NewCount = 16, UpdatedCount = 6, ImportedByUserId = analyst.Id };
        var b2 = new ImportBatchEntity { Source = ImportSource.ManualUpload, FileName = "weekly-internal-2026-11-16.xml", TargetName = "Weekly internal sweep", StartedAt = now.AddDays(-7), CompletedAt = now.AddDays(-7).AddMinutes(5), Status = ImportStatus.CompletedWithWarnings, TotalFindings = 28, NewCount = 9, UpdatedCount = 15, MarkedForVerificationCount = 3, ReopenedCount = 1, ErrorMessage = "1 host had missing OS banner.", ImportedByUserId = analyst.Id };
        var b3 = new ImportBatchEntity { Source = ImportSource.ManualUpload, FileName = "perimeter-vpn-rescan-2026-11-20.xml", TargetName = "Perimeter VPN rescan", StartedAt = now.AddDays(-3), CompletedAt = now.AddDays(-3).AddMinutes(5), Status = ImportStatus.Completed, TotalFindings = 10, NewCount = 1, UpdatedCount = 5, MarkedForVerificationCount = 4, ImportedByUserId = analyst.Id };
        var b4 = new ImportBatchEntity { Source = ImportSource.GreenboneApi, FileName = "weekly-internal-2026-11-23.xml", TargetName = "Weekly internal sweep", StartedAt = now.AddHours(-4), CompletedAt = now.AddHours(-4).AddMinutes(6), Status = ImportStatus.Completed, TotalFindings = 30, NewCount = 4, UpdatedCount = 20, MarkedForVerificationCount = 5, ReopenedCount = 1, ImportedByUserId = admin.Id };
        db.ImportBatches.AddRange(b1, b2, b3, b4);
        await db.SaveChangesAsync();

        VulnerabilityEntity V(string cve, string title, VulnerabilitySeverity sev, decimal cvss, AssetEntity a, int port, string proto, string svc, VulnerabilityStatus st, int detectedAgoDays, int dueOffsetDays, ImportBatchEntity createdB, ImportBatchEntity lastB, ImportBatchEntity? verifiedB = null)
        {
            var det = now.AddDays(-detectedAgoDays);
            return new VulnerabilityEntity
            {
                CveId = cve,
                Title = title,
                Description = $"Greenbone detected {title} ({cve}) on {a.Hostname} ({a.IpAddress}) on port {port}/{proto}.",
                Severity = sev,
                CvssScore = cvss,
                AssetId = a.Id,
                Port = port,
                Protocol = proto,
                Service = svc,
                BusinessImpact = a.BusinessImpactNotes,
                RecommendedFix = $"Apply vendor security update for {a.OperatingSystem} addressing {cve}, restart {svc}, and confirm with a Greenbone rescan.",
                OwnerUserId = a.OwnerUserId,
                DueDate = now.AddDays(dueOffsetDays),
                Status = st,
                DetectedAt = det,
                LastSeenAt = lastB.CompletedAt ?? now,
                FixedAt = st is VulnerabilityStatus.FixedAwaitingVerification or VulnerabilityStatus.Closed ? now.AddDays(-2) : null,
                ClosedAt = st == VulnerabilityStatus.Closed ? (verifiedB?.CompletedAt ?? now.AddDays(-1)) : null,
                CreatedByImportBatchId = createdB.Id,
                LastImportBatchId = lastB.Id,
                VerifiedByImportBatchId = verifiedB?.Id
            };
        }

        var vulns = new List<VulnerabilityEntity>
        {
            V("CVE-2024-21887", "Ivanti Connect Secure command injection", VulnerabilitySeverity.Critical, 9.1m, assets[0], 443, "tcp", "https", VulnerabilityStatus.InProgress, 1, 6, b4, b4),
            V("CVE-2024-3400", "PAN-OS GlobalProtect command injection", VulnerabilitySeverity.Critical, 10.0m, assets[1], 443, "tcp", "https", VulnerabilityStatus.Open, 18, -11, b1, b4),
            V("CVE-2024-21413", "Microsoft Outlook MonikerLink RCE", VulnerabilitySeverity.Critical, 9.8m, assets[4], 443, "tcp", "ews", VulnerabilityStatus.Open, 16, -9, b1, b4),
            V("CVE-2024-3094", "xz-utils backdoor in liblzma", VulnerabilitySeverity.Critical, 10.0m, assets[6], 22, "tcp", "ssh", VulnerabilityStatus.Closed, 13, -6, b1, b2, b3),
            V("CVE-2024-1709", "ScreenConnect authentication bypass", VulnerabilitySeverity.Critical, 10.0m, assets[2], 8040, "tcp", "http", VulnerabilityStatus.Open, 12, -5, b1, b4),
            V("CVE-2024-4577", "PHP-CGI argument injection", VulnerabilitySeverity.Critical, 9.8m, assets[5], 443, "tcp", "https", VulnerabilityStatus.Open, 14, -7, b1, b4),
            V("CVE-2023-4966", "Citrix NetScaler session token leak", VulnerabilitySeverity.Critical, 9.4m, assets[0], 8443, "tcp", "https", VulnerabilityStatus.FixedAwaitingVerification, 11, -4, b1, b3),
            V("CVE-2024-21762", "FortiOS SSL VPN out-of-bounds write", VulnerabilitySeverity.Critical, 9.6m, assets[1], 10443, "tcp", "https", VulnerabilityStatus.InProgress, 15, -8, b1, b4),
            V("CVE-2024-6387", "OpenSSH regreSSHion race condition", VulnerabilitySeverity.High, 8.1m, assets[2], 22, "tcp", "ssh", VulnerabilityStatus.Open, 22, -8, b1, b4),
            V("CVE-2023-44487", "HTTP/2 rapid reset DoS", VulnerabilitySeverity.High, 7.5m, assets[5], 443, "tcp", "https", VulnerabilityStatus.InProgress, 9, 5, b2, b4),
            V("CVE-2024-21338", "Windows kernel elevation of privilege", VulnerabilitySeverity.High, 7.8m, assets[2], 445, "tcp", "smb", VulnerabilityStatus.Open, 17, -3, b1, b4),
            V("CVE-2024-20353", "Cisco ASA web services DoS", VulnerabilitySeverity.High, 8.6m, assets[1], 8443, "tcp", "https", VulnerabilityStatus.FixedAwaitingVerification, 12, 2, b1, b3),
            V("CVE-2024-0519", "Chromium V8 out-of-bounds memory access", VulnerabilitySeverity.High, 8.8m, assets[7], 0, "local", "browser", VulnerabilityStatus.InProgress, 8, 6, b2, b4),
            V("CVE-2023-36884", "Microsoft Office HTML RCE", VulnerabilitySeverity.High, 8.8m, assets[7], 445, "tcp", "smb", VulnerabilityStatus.Open, 18, -4, b1, b4),
            V("CVE-2023-4863", "libwebp heap buffer overflow", VulnerabilitySeverity.High, 8.8m, assets[6], 8080, "tcp", "http", VulnerabilityStatus.Closed, 19, -5, b1, b2, b4),
            V("CVE-2024-26169", "Windows Error Reporting EoP", VulnerabilitySeverity.High, 7.8m, assets[4], 445, "tcp", "smb", VulnerabilityStatus.InProgress, 7, 7, b2, b4),
            V("CVE-2023-48795", "OpenSSH Terrapin prefix truncation", VulnerabilitySeverity.Medium, 5.9m, assets[3], 22, "tcp", "ssh", VulnerabilityStatus.FixedAwaitingVerification, 21, 9, b1, b3),
            V("CVE-2023-5678", "OpenSSL excessive DH key generation time", VulnerabilitySeverity.Medium, 5.3m, assets[5], 8443, "tcp", "https", VulnerabilityStatus.Open, 13, 17, b1, b4),
            V("CVE-2022-0778", "OpenSSL BN_mod_sqrt infinite loop", VulnerabilitySeverity.Medium, 6.5m, assets[3], 443, "tcp", "https", VulnerabilityStatus.Closed, 14, 16, b1, b2, b4),
            V("CVE-2023-38546", "curl cookie injection with none file", VulnerabilitySeverity.Medium, 4.8m, assets[6], 443, "tcp", "https", VulnerabilityStatus.InProgress, 7, 23, b2, b4),
            V("CVE-2023-4911", "glibc Looney Tunables buffer overflow", VulnerabilitySeverity.Medium, 6.8m, assets[3], 22, "tcp", "ssh", VulnerabilityStatus.FixedAwaitingVerification, 14, 16, b1, b3),
            V("CVE-2024-27316", "Apache HTTP Server CONTINUATION flood", VulnerabilitySeverity.Medium, 6.5m, assets[5], 80, "tcp", "http", VulnerabilityStatus.Open, 3, 27, b3, b4),
            V("CVE-2023-51385", "OpenSSH OS command injection via username", VulnerabilitySeverity.Low, 3.7m, assets[3], 2222, "tcp", "ssh", VulnerabilityStatus.Open, 14, 76, b1, b4),
            V("CVE-2023-29491", "ncurses local privilege escalation", VulnerabilitySeverity.Low, 3.3m, assets[6], 0, "local", "os", VulnerabilityStatus.Closed, 14, 76, b1, b2, b4),
            V("CVE-2022-40674", "libexpat heap use-after-free", VulnerabilitySeverity.Low, 3.9m, assets[4], 80, "tcp", "http", VulnerabilityStatus.AcceptedRisk, 7, 83, b2, b4),
            V("CVE-2023-2650", "OpenSSL OBJ_obj2txt processing delay", VulnerabilitySeverity.Low, 3.5m, assets[0], 80, "tcp", "http", VulnerabilityStatus.Open, 1, 89, b4, b4),
            V("CVE-2021-41617", "OpenSSH AuthorizedKeysCommand supplemental groups", VulnerabilitySeverity.Low, 3.1m, assets[2], 2222, "tcp", "ssh", VulnerabilityStatus.AcceptedRisk, 7, 83, b2, b4),
            V("NVT-TLS-EXP-01", "TLS certificate expires within 30 days", VulnerabilitySeverity.Info, 0.0m, assets[5], 8443, "tcp", "https", VulnerabilityStatus.Open, 1, 179, b4, b4),
            V("NVT-SSH-BAN-01", "SSH server version banner disclosed", VulnerabilitySeverity.Info, 0.0m, assets[3], 2200, "tcp", "ssh", VulnerabilityStatus.FixedAwaitingVerification, 7, 173, b2, b3),
            V("NVT-ICMP-TS-01", "ICMP timestamp reply enabled", VulnerabilitySeverity.Info, 0.0m, assets[7], 0, "icmp", "icmp", VulnerabilityStatus.Open, 1, 179, b4, b4)
        };
        db.Vulnerabilities.AddRange(vulns);
        await db.SaveChangesAsync();

        db.VulnerabilityHistory.AddRange(
            new VulnerabilityHistoryEntity { VulnerabilityId = vulns[0].Id, ChangeType = VulnerabilityChangeType.Imported, NewValue = "Open", Note = "Imported from weekly-internal-2026-11-23.xml", ImportBatchId = b4.Id, ChangedAt = now.AddHours(-4) },
            new VulnerabilityHistoryEntity { VulnerabilityId = vulns[0].Id, ChangeType = VulnerabilityChangeType.OwnerAssigned, NewValue = owner.FullName, Note = "Auto-assigned from asset registry", ChangedByUserId = analyst.Id, ImportBatchId = b4.Id, ChangedAt = now.AddHours(-3) },
            new VulnerabilityHistoryEntity { VulnerabilityId = vulns[0].Id, ChangeType = VulnerabilityChangeType.StatusChanged, OldValue = "Open", NewValue = "InProgress", Note = "Maintenance window booked for patch rollout", ChangedByUserId = owner.Id, ChangedAt = now.AddHours(-2) },
            new VulnerabilityHistoryEntity { VulnerabilityId = vulns[3].Id, ChangeType = VulnerabilityChangeType.RescanVerified, OldValue = "FixedAwaitingVerification", NewValue = "Verified", Note = "Absent from rescan batch #3", ImportBatchId = b3.Id, ChangedAt = now.AddDays(-3) },
            new VulnerabilityHistoryEntity { VulnerabilityId = vulns[3].Id, ChangeType = VulnerabilityChangeType.Closed, OldValue = "FixedAwaitingVerification", NewValue = "Closed", Note = "Closed with verified rescan evidence", ChangedByUserId = analyst.Id, ImportBatchId = b3.Id, ChangedAt = now.AddDays(-3) },
            new VulnerabilityHistoryEntity { VulnerabilityId = vulns[7].Id, ChangeType = VulnerabilityChangeType.Reopened, OldValue = "FixedAwaitingVerification", NewValue = "InProgress", Note = "Still detected in weekly-internal-2026-11-23.xml; reopened", ImportBatchId = b4.Id, ChangedAt = now.AddHours(-4) }
        );

        db.Alerts.AddRange(
            new AlertEntity { Type = AlertEventType.SlaOverdue, Message = "SLA breach: CVE-2024-3400 on fw-edge-01 is 11 days overdue.", VulnerabilityId = vulns[1].Id, RecipientUserId = admin.Id, IsRead = false, CreatedAt = now.AddHours(-3) },
            new AlertEntity { Type = AlertEventType.SlaOverdue, Message = "SLA breach: CVE-2024-21413 on mail-ex-01 is 9 days overdue.", VulnerabilityId = vulns[2].Id, RecipientUserId = admin.Id, IsRead = false, CreatedAt = now.AddHours(-3) },
            new AlertEntity { Type = AlertEventType.CriticalFinding, Message = "Critical finding imported: CVE-2024-21887 on vpn-gw-01.", VulnerabilityId = vulns[0].Id, RecipientUserId = owner.Id, IsRead = false, CreatedAt = now.AddHours(-4) },
            new AlertEntity { Type = AlertEventType.RescanResult, Message = "Rescan verified closure of CVE-2024-3094 on build-runner-03.", VulnerabilityId = vulns[3].Id, RecipientUserId = analyst.Id, IsRead = true, CreatedAt = now.AddDays(-3) },
            new AlertEntity { Type = AlertEventType.ImportFailed, Message = "Import warning: 1 host missing OS banner in weekly-internal-2026-11-16.xml.", RecipientUserId = analyst.Id, IsRead = true, CreatedAt = now.AddDays(-7) }
        );

        db.AuditLogs.AddRange(
            new AuditLogEntity { UserId = admin.Id, Action = "ImportCompleted", TargetType = "ImportBatch", TargetId = b4.Id.ToString(), Details = "weekly-internal-2026-11-23.xml: 4 new, 20 updated, 5 awaiting verification, 1 reopened", IpAddress = "10.20.1.12", Timestamp = now.AddHours(-4) },
            new AuditLogEntity { UserId = owner.Id, Action = "StatusChanged", TargetType = "Vulnerability", TargetId = vulns[0].Id.ToString(), Details = "Changed CVE-2024-21887 from Open to InProgress", IpAddress = "10.40.12.5", Timestamp = now.AddHours(-2) },
            new AuditLogEntity { UserId = analyst.Id, Action = "FindingClosed", TargetType = "Vulnerability", TargetId = vulns[3].Id.ToString(), Details = "Closed CVE-2024-3094 after verified rescan", IpAddress = "10.20.1.44", Timestamp = now.AddDays(-3) }
        );

        db.ReportRecords.AddRange(
            new ReportRecordEntity { Name = "Executive Security Summary - Nov 2026", Type = "Executive summary", Format = ReportFileFormat.Pdf, FiltersJson = "{\"scope\":\"all\"}", CreatedByUserId = admin.Id, CreatedAt = now.AddHours(-2), FilePath = "/reports/exec-2026-11.pdf" },
            new ReportRecordEntity { Name = "Overdue SLA Escalation List", Type = "Overdue remediation", Format = ReportFileFormat.Csv, FiltersJson = "{\"overdueOnly\":true}", CreatedByUserId = analyst.Id, CreatedAt = now.AddDays(-1), FilePath = "/reports/overdue.csv" }
        );

        await db.SaveChangesAsync();
    }

    private static async Task<ApplicationUser> EnsureUserAsync(
        UserManager<ApplicationUser> userManager,
        string email,
        string password,
        string fullName,
        string department,
        string role)
    {
        var user = await userManager.FindByEmailAsync(email);
        if (user is null)
        {
            user = new ApplicationUser
            {
                UserName = email,
                Email = email,
                EmailConfirmed = true,
                FullName = fullName,
                Department = department,
                IsActive = true,
                LastLoginAt = DateTime.UtcNow.AddHours(-1)
            };
            var res = await userManager.CreateAsync(user, password);
            if (!res.Succeeded)
            {
                throw new InvalidOperationException($"Failed creating seed user {email}: {string.Join("; ", res.Errors.Select(e => e.Description))}");
            }
        }

        if (!await userManager.IsInRoleAsync(user, role))
        {
            await userManager.AddToRoleAsync(user, role);
        }

        return user;
    }
}
