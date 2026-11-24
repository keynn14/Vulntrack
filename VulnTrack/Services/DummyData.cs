using VulnTrack.Models;

namespace VulnTrack.Services;

public record GreenboneSync(DateTime At, string Task, string ScanConfig, int Hosts, string Host, int Port);

public static class DummyData
{
    public static readonly DateOnly Today = new(2026, 11, 23);

    public static readonly GreenboneSync LastSync = new(
        new DateTime(2026, 11, 23, 6, 0, 0),
        "Weekly internal sweep",
        "Full and fast",
        312,
        "gvm-scanner.internal.local",
        9390
    );

    public static readonly List<AppUser> Users = new()
    {
        new()
        {
            Id = "USR-01",
            FullName = "Andrea Reyes",
            Email = "andrea.reyes@vulntrack.local",
            Role = Roles.Administrator,
            Team = "Security Office",
            IsActive = true,
            LastLogin = new DateTime(2026, 11, 23, 8, 15, 0)
        },
        new()
        {
            Id = "USR-02",
            FullName = "Marco Villanueva",
            Email = "marco.villanueva@vulntrack.local",
            Role = Roles.SecurityAnalyst,
            Team = "SOC",
            IsActive = true,
            LastLogin = new DateTime(2026, 11, 23, 7, 50, 0)
        },
        new()
        {
            Id = "USR-03",
            FullName = "Priya Nair",
            Email = "priya.nair@vulntrack.local",
            Role = Roles.SecurityAnalyst,
            Team = "SOC",
            IsActive = true,
            LastLogin = new DateTime(2026, 11, 22, 19, 30, 0)
        },
        new()
        {
            Id = "USR-04",
            FullName = "Maria Santos",
            Email = "maria.santos@vulntrack.local",
            Role = Roles.AssetOwner,
            Team = "Network",
            IsActive = true,
            LastLogin = new DateTime(2026, 11, 23, 8, 5, 0)
        },
        new()
        {
            Id = "USR-05",
            FullName = "Joel Lim",
            Email = "joel.lim@vulntrack.local",
            Role = Roles.AssetOwner,
            Team = "Radiology IT",
            IsActive = true,
            LastLogin = new DateTime(2026, 11, 22, 16, 40, 0)
        },
        new()
        {
            Id = "USR-06",
            FullName = "Ken Tan",
            Email = "ken.tan@vulntrack.local",
            Role = Roles.AssetOwner,
            Team = "Finance IT",
            IsActive = false,
            LastLogin = new DateTime(2026, 10, 14, 11, 10, 0)
        }
    };

    public static readonly List<Asset> Assets = new()
    {
        new() { Id = "AST-01", Hostname = "vpn-gw-01", IpAddress = "10.20.0.4", OperatingSystem = "Ivanti Connect Secure 22.6", Owner = "Maria Santos", Team = "Network", Criticality = BusinessImpact.Critical, Environment = "Production", LastScanned = new DateOnly(2026, 11, 23), BusinessImpactNotes = "Primary remote-access VPN gateway serving all remote clinical and corporate staff." },
        new() { Id = "AST-02", Hostname = "fw-edge-01", IpAddress = "10.20.0.1", OperatingSystem = "PAN-OS 11.1", Owner = "Maria Santos", Team = "Network", Criticality = BusinessImpact.Critical, Environment = "Production", LastScanned = new DateOnly(2026, 11, 23), BusinessImpactNotes = "Perimeter firewall protecting primary internet ingress and egress." },
        new() { Id = "AST-03", Hostname = "bastion-02", IpAddress = "10.20.2.12", OperatingSystem = "Ubuntu 24.04 LTS", Owner = "Maria Santos", Team = "Network", Criticality = BusinessImpact.High, Environment = "Production", LastScanned = new DateOnly(2026, 11, 23), BusinessImpactNotes = "Privileged SSH jump host for production infrastructure administration." },
        new() { Id = "AST-04", Hostname = "srv-pacs-02", IpAddress = "10.40.12.20", OperatingSystem = "Windows Server 2022", Owner = "Joel Lim", Team = "Radiology IT", Criticality = BusinessImpact.Critical, Environment = "Production", LastScanned = new DateOnly(2026, 11, 23), BusinessImpactNotes = "Picture Archiving and Communication System storing diagnostic imaging records." },
        new() { Id = "AST-05", Hostname = "ris-app-01", IpAddress = "10.40.12.35", OperatingSystem = "RHEL 9.3", Owner = "Joel Lim", Team = "Radiology IT", Criticality = BusinessImpact.High, Environment = "Production", LastScanned = new DateOnly(2026, 11, 23), BusinessImpactNotes = "Radiology Information System application server for exam scheduling and reporting." },
        new() { Id = "AST-06", Hostname = "mail-ex-01", IpAddress = "10.30.4.10", OperatingSystem = "Windows Server 2019", Owner = "Daniel Cruz", Team = "Messaging", Criticality = BusinessImpact.High, Environment = "Production", LastScanned = new DateOnly(2026, 11, 23), BusinessImpactNotes = "Internal Exchange mail relay and mailbox server." },
        new() { Id = "AST-07", Hostname = "web-portal-01", IpAddress = "10.50.1.18", OperatingSystem = "Debian 12", Owner = "Ana Lopez", Team = "Web", Criticality = BusinessImpact.High, Environment = "Production", LastScanned = new DateOnly(2026, 11, 23), BusinessImpactNotes = "Public-facing patient and partner self-service web portal." },
        new() { Id = "AST-08", Hostname = "build-runner-03", IpAddress = "10.60.8.41", OperatingSystem = "Ubuntu 22.04 LTS", Owner = "Liza Gomez", Team = "DevOps", Criticality = BusinessImpact.Medium, Environment = "Staging", LastScanned = new DateOnly(2026, 11, 23), BusinessImpactNotes = "CI/CD build agent compiling internal application containers." },
        new() { Id = "AST-09", Hostname = "db-his-01", IpAddress = "10.40.10.5", OperatingSystem = "RHEL 9.2", Owner = "Joel Lim", Team = "Radiology IT", Criticality = BusinessImpact.Critical, Environment = "Production", LastScanned = new DateOnly(2026, 11, 23), BusinessImpactNotes = "Hospital Information System relational database cluster." },
        new() { Id = "AST-10", Hostname = "ws-fin-114", IpAddress = "10.70.19.114", OperatingSystem = "Windows 11 Pro", Owner = "Ken Tan", Team = "Finance IT", Criticality = BusinessImpact.Low, Environment = "Corporate", LastScanned = new DateOnly(2026, 11, 20), BusinessImpactNotes = "Finance reconciliation workstation on isolated corporate VLAN." }
    };

    public static readonly List<Vulnerability> Vulnerabilities = BuildVulnerabilities();

    public static readonly List<ImportRecord> Imports = new()
    {
        new() { Id = "IMP-2026-1123", FileName = "weekly-internal-2026-11-23.xml", Source = "Greenbone GMP", ScanTask = "Weekly internal sweep", ImportedAt = new DateTime(2026, 11, 23, 6, 12, 0), ImportedBy = "Marco Villanueva", NewFindings = 12, UpdatedFindings = 126, MarkedFixed = 10, Status = "Completed", Notes = "312 hosts matched against asset registry." },
        new() { Id = "IMP-2026-1120", FileName = "perimeter-vpn-rescan-2026-11-20.xml", Source = "Greenbone GMP", ScanTask = "Perimeter VPN rescan", ImportedAt = new DateTime(2026, 11, 20, 14, 40, 0), ImportedBy = "Priya Nair", NewFindings = 1, UpdatedFindings = 7, MarkedFixed = 3, Status = "Completed", Notes = "Targeted rescan for vpn-gw-01 and bastion-02." },
        new() { Id = "IMP-2026-1116", FileName = "weekly-internal-2026-11-16.xml", Source = "Greenbone GMP", ScanTask = "Weekly internal sweep", ImportedAt = new DateTime(2026, 11, 16, 6, 15, 0), ImportedBy = "Marco Villanueva", NewFindings = 14, UpdatedFindings = 22, MarkedFixed = 6, Status = "Completed with warnings", Notes = "2 hosts had no asset owner in registry; assigned to SOC triage." },
        new() { Id = "IMP-2026-1114", FileName = "radiology-segment-upload.csv", Source = "File upload (CSV)", ScanTask = "Radiology segment upload", ImportedAt = new DateTime(2026, 11, 14, 17, 5, 0), ImportedBy = "Andrea Reyes", NewFindings = 0, UpdatedFindings = 0, MarkedFixed = 0, Status = "Failed", Notes = "Missing required CVE/NVT column on line 42." },
        new() { Id = "IMP-2026-1109", FileName = "weekly-internal-2026-11-09.xml", Source = "Greenbone GMP", ScanTask = "Weekly internal sweep", ImportedAt = new DateTime(2026, 11, 9, 6, 18, 0), ImportedBy = "Marco Villanueva", NewFindings = 11, UpdatedFindings = 16, MarkedFixed = 5, Status = "Completed", Notes = "Full and fast scan across production subnets." }
    };

    public static readonly List<AlertItem> Alerts = new()
    {
        new() { Id = "ALT-01", Type = AlertType.SlaOverdue, Title = "SLA breach: CVE-2024-3400 on fw-edge-01", Message = "Critical PAN-OS GlobalProtect finding is 11 days past its 7-day SLA.", Severity = Severity.Critical, CreatedAt = new DateTime(2026, 11, 23, 6, 20, 0), IsRead = false, Link = "/vulnerabilities/CVE-2024-3400" },
        new() { Id = "ALT-02", Type = AlertType.SlaOverdue, Title = "SLA breach: CVE-2024-21413 on mail-ex-01", Message = "Outlook MonikerLink RCE assigned to Daniel Cruz is 9 days overdue.", Severity = Severity.Critical, CreatedAt = new DateTime(2026, 11, 23, 6, 20, 0), IsRead = false, Link = "/vulnerabilities/CVE-2024-21413" },
        new() { Id = "ALT-03", Type = AlertType.CriticalImported, Title = "Critical finding imported: CVE-2024-21887 on vpn-gw-01", Message = "Detected during weekly-internal-2026-11-23.xml and assigned to Maria Santos.", Severity = Severity.Critical, CreatedAt = new DateTime(2026, 11, 23, 6, 12, 0), IsRead = false, Link = "/vulnerabilities/CVE-2024-21887" },
        new() { Id = "ALT-04", Type = AlertType.RescanResult, Title = "Rescan confirmed fix: CVE-2023-4966 on vpn-gw-01", Message = "Greenbone rescan no longer detects session token leak. Ready for closure.", Severity = Severity.Info, CreatedAt = new DateTime(2026, 11, 22, 18, 10, 0), IsRead = false, Link = "/verification" },
        new() { Id = "ALT-05", Type = AlertType.SlaOverdue, Title = "SLA breach: CVE-2024-6387 on srv-pacs-02", Message = "OpenSSH regreSSHion on Radiology PACS server is 8 days overdue.", Severity = Severity.High, CreatedAt = new DateTime(2026, 11, 22, 9, 0, 0), IsRead = false, Link = "/vulnerabilities/CVE-2024-6387" },
        new() { Id = "ALT-06", Type = AlertType.ImportFailed, Title = "Import failed: radiology-segment-upload.csv", Message = "File validation failed on line 42 (missing CVE/NVT identifier column).", Severity = Severity.High, CreatedAt = new DateTime(2026, 11, 14, 17, 5, 0), IsRead = true, Link = "/import" },
        new() { Id = "ALT-07", Type = AlertType.RescanResult, Title = "Rescan verified 3 fixes", Message = "CVE-2024-3094 on build-runner-03 and two Medium findings passed verification.", Severity = Severity.Info, CreatedAt = new DateTime(2026, 11, 18, 15, 25, 0), IsRead = true, Link = "/verification" }
    };

    public static readonly List<AuditEntry> AuditLog = new()
    {
        new() { Id = "AUD-1010", Timestamp = new DateTime(2026, 11, 23, 8, 22, 0), Actor = "Marco Villanueva", Action = "Nudge sent", ActionType = "Finding", Target = "VT-1043 (fw-edge-01)", Details = "SLA reminder sent to Maria Santos", IpAddress = "10.20.1.44" },
        new() { Id = "AUD-1009", Timestamp = new DateTime(2026, 11, 23, 6, 12, 0), Actor = "Marco Villanueva", Action = "Scan imported", ActionType = "Scan", Target = "IMP-2026-1123", Details = "weekly-internal-2026-11-23.xml: 12 new, 126 updated, 10 awaiting verification", IpAddress = "10.20.1.44" },
        new() { Id = "AUD-1008", Timestamp = new DateTime(2026, 11, 22, 16, 45, 0), Actor = "Maria Santos", Action = "Marked fixed", ActionType = "Finding", Target = "VT-1027 (bastion-02)", Details = "Upgraded OpenSSH; awaiting Greenbone rescan", IpAddress = "10.20.4.18" },
        new() { Id = "AUD-1007", Timestamp = new DateTime(2026, 11, 21, 14, 15, 0), Actor = "Maria Santos", Action = "Marked fixed", ActionType = "Finding", Target = "VT-1055 (vpn-gw-01)", Details = "Applied NetScaler patch; awaiting Greenbone rescan", IpAddress = "10.20.4.18" },
        new() { Id = "AUD-1006", Timestamp = new DateTime(2026, 11, 20, 14, 42, 0), Actor = "Priya Nair", Action = "Scan imported", ActionType = "Scan", Target = "IMP-2026-1120", Details = "perimeter-vpn-rescan-2026-11-20.xml: 1 new, 3 awaiting verification", IpAddress = "10.20.1.51" },
        new() { Id = "AUD-1005", Timestamp = new DateTime(2026, 11, 18, 15, 25, 0), Actor = "Priya Nair", Action = "Finding closed", ActionType = "Verification", Target = "VT-1031 (build-runner-03)", Details = "Verified absent in rescan IMP-2026-1116", IpAddress = "10.20.1.51" },
        new() { Id = "AUD-1004", Timestamp = new DateTime(2026, 11, 16, 9, 10, 0), Actor = "Andrea Reyes", Action = "User disabled", ActionType = "User", Target = "USR-06 (Ken Tan)", Details = "Account deactivated following department transfer", IpAddress = "10.20.1.12" },
        new() { Id = "AUD-1003", Timestamp = new DateTime(2026, 11, 14, 17, 20, 0), Actor = "Andrea Reyes", Action = "Import failed", ActionType = "Scan", Target = "IMP-2026-1114", Details = "Validation rejected malformed CSV upload", IpAddress = "10.20.1.12" },
        new() { Id = "AUD-1002", Timestamp = new DateTime(2026, 11, 12, 10, 5, 0), Actor = "Marco Villanueva", Action = "Owner assigned", ActionType = "Finding", Target = "VT-1042 (vpn-gw-01)", Details = "Assigned CVE-2024-21887 to Maria Santos (Network)", IpAddress = "10.20.1.44" },
        new() { Id = "AUD-1001", Timestamp = new DateTime(2026, 11, 10, 8, 30, 0), Actor = "Andrea Reyes", Action = "SLA policy updated", ActionType = "Settings", Target = "Global SLA", Details = "Critical 7d, High 14d, Medium 30d, Low 90d", IpAddress = "10.20.1.12" }
    };

    public static readonly List<ReportRecord> RecentReports = new()
    {
        new() { Id = "RPT-204", Name = "Executive Security Summary — Nov 2026", ReportType = "Executive summary", CreatedBy = "Andrea Reyes", CreatedAt = new DateTime(2026, 11, 23, 7, 30, 0), Format = "PDF", ScopeSummary = "All assets · Nov 1–23" },
        new() { Id = "RPT-203", Name = "Overdue SLA Escalation List", ReportType = "Overdue remediation", CreatedBy = "Marco Villanueva", CreatedAt = new DateTime(2026, 11, 22, 16, 10, 0), Format = "CSV", ScopeSummary = "Critical & High · Overdue" },
        new() { Id = "RPT-202", Name = "Perimeter Closure Verification Evidence", ReportType = "Closure verification", CreatedBy = "Priya Nair", CreatedAt = new DateTime(2026, 11, 20, 15, 0, 0), Format = "PDF", ScopeSummary = "Network · Verified rescans" },
        new() { Id = "RPT-201", Name = "Radiology IT Open Findings Register", ReportType = "Open findings", CreatedBy = "Joel Lim", CreatedAt = new DateTime(2026, 11, 18, 11, 45, 0), Format = "CSV", ScopeSummary = "Radiology IT · Open & In Progress" },
        new() { Id = "RPT-200", Name = "Monthly Compliance Audit Trail", ReportType = "Audit", CreatedBy = "Andrea Reyes", CreatedAt = new DateTime(2026, 11, 1, 9, 0, 0), Format = "CSV", ScopeSummary = "All users · Oct 2026" }
    };

    public static readonly DashboardSnapshot Snapshot = new(
        TotalOpen: 148,
        Critical: 21,
        Overdue: 17,
        ClosedThisMonth: 96,
        CriticalOlderThan7: 5,
        SeverityCounts: new Dictionary<Severity, int>
        {
            [Severity.Critical] = 21,
            [Severity.High] = 46,
            [Severity.Medium] = 52,
            [Severity.Low] = 22,
            [Severity.Info] = 7
        },
        StatusCounts: new Dictionary<FindingStatus, int>
        {
            [FindingStatus.Open] = 62,
            [FindingStatus.InProgress] = 54,
            [FindingStatus.FixedAwaitingVerification] = 32,
            [FindingStatus.Closed] = 96,
            [FindingStatus.AcceptedRisk] = 9
        },
        WeekLabels: Enumerable.Range(0, 12)
            .Select(i => Today.AddDays(-7 * (11 - i)).ToString("d MMM"))
            .ToArray(),
        OpenedWeekly: new double[] { 22, 18, 25, 30, 27, 21, 26, 33, 24, 19, 23, 20 },
        ClosedWeekly: new double[] { 15, 17, 19, 22, 24, 20, 25, 27, 28, 24, 26, 29 },
        TotalOpenTrend: new double[] { 161, 158, 160, 155, 152, 150, 148 },
        CriticalTrend: new double[] { 27, 26, 24, 25, 23, 22, 21 },
        OverdueTrend: new double[] { 12, 13, 15, 14, 16, 18, 17 },
        ClosedTrend: new double[] { 40, 52, 61, 70, 78, 88, 96 },
        TotalOpenDelta: "13 fewer than last month",
        TotalOpenDeltaGood: true,
        CriticalDelta: "6 fewer than last month",
        CriticalDeltaGood: true,
        OverdueDelta: "5 more than last week",
        OverdueDeltaGood: false,
        ClosedDelta: "18% more than October",
        ClosedDeltaGood: true
    );

    public static int UnreadAlertCount => Alerts.Count(a => !a.IsRead);

    public static int OpenFindingsBadge => Snapshot.TotalOpen;

    public static bool HasPendingVerification =>
        Vulnerabilities.Any(v => v.Status == FindingStatus.FixedAwaitingVerification);

    public static AppUser? FindUser(string name) =>
        Users.FirstOrDefault(u => string.Equals(u.FullName, name, StringComparison.OrdinalIgnoreCase));

    public static Vulnerability? FindVulnerability(string cveOrId) =>
        Vulnerabilities.FirstOrDefault(v =>
            string.Equals(v.Cve, cveOrId, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(v.Id, cveOrId, StringComparison.OrdinalIgnoreCase));

    private static List<Vulnerability> BuildVulnerabilities()
    {
        var byHost = Assets.ToDictionary(a => a.Hostname);
        var list = new List<Vulnerability>
        {
            Make("VT-1042", "CVE-2024-21887", "Ivanti Connect Secure command injection", Severity.Critical, 9.1, byHost["vpn-gw-01"], new DateOnly(2026, 11, 23), FindingStatus.InProgress, new DateOnly(2026, 11, 23), "IMP-2026-1123", new DateOnly(2026, 11, 30), "443/tcp (HTTPS)"),
            Make("VT-1043", "CVE-2024-3400", "PAN-OS GlobalProtect command injection", Severity.Critical, 10.0, byHost["fw-edge-01"], new DateOnly(2026, 11, 5), FindingStatus.Open, new DateOnly(2026, 11, 20), "IMP-2026-1109", new DateOnly(2026, 11, 12), "443/tcp (GlobalProtect)"),
            Make("VT-1038", "CVE-2024-21413", "Microsoft Outlook MonikerLink remote code execution", Severity.Critical, 9.8, byHost["mail-ex-01"], new DateOnly(2026, 11, 7), FindingStatus.Open, new DateOnly(2026, 11, 18), "IMP-2026-1109", new DateOnly(2026, 11, 14), "443/tcp (EWS/OWA)"),
            Make("VT-1031", "CVE-2024-3094", "xz-utils backdoor in liblzma", Severity.Critical, 10.0, byHost["build-runner-03"], new DateOnly(2026, 11, 10), FindingStatus.Closed, new DateOnly(2026, 11, 18), "IMP-2026-1116", null, "22/tcp (OpenSSH)"),
            Make("VT-1027", "CVE-2023-48795", "OpenSSH Terrapin prefix truncation", Severity.Medium, 5.9, byHost["bastion-02"], new DateOnly(2026, 11, 2), FindingStatus.FixedAwaitingVerification, new DateOnly(2026, 11, 22), "IMP-2026-1116", null, "22/tcp (OpenSSH)"),
            Make("VT-1050", "CVE-2024-6387", "OpenSSH regreSSHion race condition", Severity.High, 8.1, byHost["srv-pacs-02"], new DateOnly(2026, 11, 1), FindingStatus.Open, new DateOnly(2026, 11, 16), "IMP-2026-1109", new DateOnly(2026, 11, 15), "22/tcp (OpenSSH)"),
            Make("VT-1051", "CVE-2024-4577", "PHP-CGI argument injection", Severity.Critical, 9.8, byHost["web-portal-01"], new DateOnly(2026, 11, 9), FindingStatus.Open, new DateOnly(2026, 11, 19), "IMP-2026-1109", new DateOnly(2026, 11, 16), "443/tcp (Apache/PHP)"),
            Make("VT-1055", "CVE-2023-4966", "Citrix NetScaler session token leak", Severity.Critical, 9.4, byHost["vpn-gw-01"], new DateOnly(2026, 11, 12), FindingStatus.FixedAwaitingVerification, new DateOnly(2026, 11, 21), "IMP-2026-1120", null, "443/tcp (HTTPS)"),
            Make("VT-1060", "CVE-2024-1709", "ScreenConnect authentication bypass", Severity.Critical, 10.0, byHost["srv-pacs-02"], new DateOnly(2026, 11, 11), FindingStatus.Open, new DateOnly(2026, 11, 22), "IMP-2026-1116", new DateOnly(2026, 11, 18), "8040/tcp (Remote Support)"),
            Make("VT-1061", "CVE-2023-34362", "MOVEit Transfer SQL injection", Severity.Critical, 9.8, byHost["db-his-01"], new DateOnly(2026, 11, 19), FindingStatus.InProgress, new DateOnly(2026, 11, 22), "IMP-2026-1123", new DateOnly(2026, 11, 26), "443/tcp (HTTPS)"),
            Make("VT-1062", "CVE-2024-21762", "FortiOS out-of-bounds write", Severity.Critical, 9.6, byHost["ris-app-01"], new DateOnly(2026, 11, 6), FindingStatus.Open, new DateOnly(2026, 11, 15), "IMP-2026-1109", null, "443/tcp (SSL VPN)")
        };

        // Configure verification states for core FixedAwaitingVerification items
        var vt1055 = list.First(v => v.Id == "VT-1055");
        vt1055.FixedBy = "Maria Santos";
        vt1055.FixedOn = new DateOnly(2026, 11, 21);
        vt1055.LastRescanAt = new DateTime(2026, 11, 22, 2, 14, 0);
        vt1055.RescanResult = RescanResult.ConfirmedFixed;

        var vt1027 = list.First(v => v.Id == "VT-1027");
        vt1027.FixedBy = "Maria Santos";
        vt1027.FixedOn = new DateOnly(2026, 11, 22);
        vt1027.LastRescanAt = new DateTime(2026, 11, 23, 2, 18, 0);
        vt1027.RescanResult = RescanResult.StillVulnerable;

        var templates = new (string Cve, string Title, Severity Sev, double Cvss, string Port)[]
        {
            ("CVE-2024-23897", "Jenkins CLI arbitrary file read", Severity.Critical, 9.8, "8080/tcp (HTTP)"),
            ("CVE-2023-44487", "HTTP/2 rapid reset stream denial of service", Severity.High, 7.5, "443/tcp (HTTPS)"),
            ("CVE-2024-21762", "FortiOS SSL VPN out-of-bounds write", Severity.Critical, 9.6, "443/tcp (SSL VPN)"),
            ("CVE-2023-38545", "curl SOCKS5 heap buffer overflow", Severity.Critical, 9.8, "443/tcp (HTTPS)"),
            ("CVE-2024-0519", "Chromium V8 out-of-bounds memory access", Severity.High, 8.8, "Local / Client"),
            ("CVE-2023-36884", "Microsoft Office HTML remote code execution", Severity.High, 8.8, "Local / Client"),
            ("CVE-2024-21338", "Windows kernel elevation of privilege", Severity.High, 7.8, "445/tcp (SMB)"),
            ("CVE-2023-50164", "Apache Struts path traversal file upload", Severity.Critical, 9.8, "8443/tcp (HTTPS)"),
            ("CVE-2024-20353", "Cisco ASA web services denial of service", Severity.High, 8.6, "443/tcp (HTTPS)"),
            ("CVE-2023-20198", "Cisco IOS XE web UI privilege escalation", Severity.Critical, 10.0, "443/tcp (HTTPS)"),
            ("CVE-2024-26169", "Windows error reporting elevation of privilege", Severity.High, 7.8, "Local / OS"),
            ("CVE-2023-4863", "libwebp heap buffer overflow", Severity.High, 8.8, "443/tcp (HTTPS)"),
            ("CVE-2022-0778", "OpenSSL BN_mod_sqrt infinite loop", Severity.High, 7.5, "443/tcp (TLS)"),
            ("CVE-2023-5678", "OpenSSL excessive time generating DH keys", Severity.Medium, 5.3, "443/tcp (TLS)"),
            ("N/A", "Weak SSH MAC algorithms enabled", Severity.Low, 2.6, "22/tcp (SSH)"),
            ("N/A", "TLS certificate expires in 30 days", Severity.Info, 0.0, "443/tcp (TLS)")
        };

        var rng = new Random(42);
        var importIds = new[] { "IMP-2026-1123", "IMP-2026-1120", "IMP-2026-1116", "IMP-2026-1109" };

        for (var i = 0; i < 49; i++)
        {
            var id = $"VT-{1063 + i}";
            var tmpl = templates[i % templates.Length];
            var asset = Assets[rng.Next(Assets.Count)];

            FindingStatus status;
            if (i < 7) status = FindingStatus.Open;
            else if (i < 12) status = FindingStatus.FixedAwaitingVerification;
            else if (i < 16) status = FindingStatus.Closed;
            else if (i < 18) status = FindingStatus.AcceptedRisk;
            else status = (i % 3 == 0) ? FindingStatus.InProgress : FindingStatus.Open;

            var ageDays = i < 7
                ? (SlaPolicy.DaysFor(tmpl.Sev) ?? 30) + rng.Next(2, 12)
                : rng.Next(1, Math.Max(4, (SlaPolicy.DaysFor(tmpl.Sev) ?? 40) - 1));

            var firstSeen = Today.AddDays(-ageDays);
            var lastUpdated = firstSeen.AddDays(rng.Next(0, Math.Max(1, ageDays)));
            if (lastUpdated > Today) lastUpdated = Today;

            var v = Make(
                id,
                tmpl.Cve,
                tmpl.Title,
                tmpl.Sev,
                tmpl.Cvss,
                asset,
                firstSeen,
                status,
                lastUpdated,
                importIds[rng.Next(importIds.Length)],
                null,
                tmpl.Port
            );

            if (status == FindingStatus.FixedAwaitingVerification)
            {
                v.FixedBy = asset.Owner;
                v.FixedOn = lastUpdated;
                v.RescanResult = (i % 3) switch
                {
                    0 => RescanResult.ConfirmedFixed,
                    1 => RescanResult.Pending,
                    _ => RescanResult.StillVulnerable
                };
                if (v.RescanResult != RescanResult.Pending)
                {
                    v.LastRescanAt = new DateTime(2026, 11, 23, 2, 10 + (i % 15), 0);
                }
            }

            list.Add(v);
        }

        return list;
    }

    private static Vulnerability Make(
        string id,
        string cve,
        string title,
        Severity severity,
        double cvss,
        Asset asset,
        DateOnly firstSeen,
        FindingStatus status,
        DateOnly lastUpdated,
        string importId,
        DateOnly? dueOverride = null,
        string servicePort = "443/tcp (HTTPS)")
    {
        var slaDays = SlaPolicy.DaysFor(severity);
        var dueDate = dueOverride ?? firstSeen.AddDays(slaDays ?? 180);

        var activity = new List<FindingActivity>
        {
            new(firstSeen.ToDateTime(new TimeOnly(6, 12)), "Greenbone GMP", "Imported", $"Imported from scan batch {importId} on {asset.Hostname}."),
            new(firstSeen.ToDateTime(new TimeOnly(6, 13)), "VulnTrack SLA", "Ranked", $"Ranked {severity} (CVSS {cvss:0.0}) against {asset.Criticality} business impact; due {dueDate:d MMM yyyy}."),
            new(firstSeen.ToDateTime(new TimeOnly(8, 30)), "Marco Villanueva", "Assigned", $"Assigned to {asset.Owner} ({asset.Team}).")
        };

        if (status == FindingStatus.InProgress)
        {
            activity.Add(new(lastUpdated.ToDateTime(new TimeOnly(10, 15)), asset.Owner, "Status changed", "Moved to In Progress; patch scheduled for maintenance window."));
        }
        else if (status == FindingStatus.FixedAwaitingVerification)
        {
            activity.Add(new(lastUpdated.ToDateTime(new TimeOnly(14, 20)), asset.Owner, "Marked fixed", "Owner applied vendor update. Finding remains open until Greenbone rescan confirms."));
        }
        else if (status == FindingStatus.Closed)
        {
            activity.Add(new(lastUpdated.AddDays(-1).ToDateTime(new TimeOnly(15, 0)), asset.Owner, "Marked fixed", "Patched package and restarted affected daemon."));
            activity.Add(new(lastUpdated.ToDateTime(new TimeOnly(2, 15)), "Greenbone GMP", "Rescan verified", "Targeted rescan no longer detects the vulnerability."));
            activity.Add(new(lastUpdated.ToDateTime(new TimeOnly(9, 10)), "Priya Nair", "Closed", "Closed with verified rescan evidence."));
        }

        var refs = new List<string>();
        if (!string.Equals(cve, "N/A", StringComparison.OrdinalIgnoreCase))
        {
            refs.Add($"https://nvd.nist.gov/vuln/detail/{cve}");
            refs.Add($"https://www.cve.org/CVERecord?id={cve}");
        }
        refs.Add("https://www.greenbone.net/en/vulnerability-feed/");

        return new Vulnerability
        {
            Id = id,
            Cve = cve,
            Title = title,
            Severity = severity,
            Cvss = cvss,
            AssetId = asset.Id,
            AssetName = asset.Hostname,
            Owner = asset.Owner,
            OwnerTeam = asset.Team,
            BusinessImpact = asset.Criticality,
            FirstSeen = firstSeen,
            DueDate = dueDate,
            Status = status,
            LastUpdated = lastUpdated,
            ImportId = importId,
            ServicePort = servicePort,
            Description = $"Greenbone detected {title} ({cve}) on {asset.Hostname} ({asset.IpAddress}) via {servicePort}. Unpatched instances expose the {asset.Team} service to unauthorized access or service disruption.",
            RecommendedFix = $"Apply the latest vendor security update for {asset.OperatingSystem} addressing {cve}, restart the affected service ({servicePort}), and request a Greenbone verification rescan before closing.",
            References = refs,
            FixedBy = status is FindingStatus.Closed or FindingStatus.FixedAwaitingVerification ? asset.Owner : null,
            FixedOn = status is FindingStatus.Closed or FindingStatus.FixedAwaitingVerification ? lastUpdated : null,
            LastRescanAt = status == FindingStatus.Closed ? lastUpdated.ToDateTime(new TimeOnly(2, 15)) : null,
            RescanResult = status == FindingStatus.Closed ? RescanResult.ConfirmedFixed : RescanResult.Pending,
            Activity = activity
        };
    }
}
