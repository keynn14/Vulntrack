namespace VulnTrack.Data.Entities;

public enum AssetCriticality : byte
{
    Low = 1,
    Medium = 2,
    High = 3
}

public enum VulnerabilitySeverity : byte
{
    Info = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5
}

public enum VulnerabilityStatus : byte
{
    Open = 1,
    InProgress = 2,
    FixedAwaitingVerification = 3,
    Closed = 4,
    AcceptedRisk = 5
}

public enum ImportSource : byte
{
    GreenboneApi = 1,
    ManualUpload = 2
}

public enum ImportStatus : byte
{
    Running = 1,
    Completed = 2,
    CompletedWithWarnings = 3,
    Failed = 4,
    RolledBack = 5
}

public enum VulnerabilityChangeType : byte
{
    Imported = 1,
    Ranked = 2,
    OwnerAssigned = 3,
    DueDateChanged = 4,
    StatusChanged = 5,
    Reopened = 6,
    RescanVerified = 7,
    Closed = 8,
    Comment = 9
}

public enum AlertEventType : byte
{
    CriticalFinding = 1,
    SlaOverdue = 2,
    RescanResult = 3,
    ImportFailed = 4
}

public enum ReportFileFormat : byte
{
    Pdf = 1,
    Csv = 2
}

public static class DomainEnumMappings
{
    public static VulnTrack.Models.Severity ToUiSeverity(this VulnerabilitySeverity sev) => sev switch
    {
        VulnerabilitySeverity.Critical => VulnTrack.Models.Severity.Critical,
        VulnerabilitySeverity.High => VulnTrack.Models.Severity.High,
        VulnerabilitySeverity.Medium => VulnTrack.Models.Severity.Medium,
        VulnerabilitySeverity.Low => VulnTrack.Models.Severity.Low,
        _ => VulnTrack.Models.Severity.Info
    };

    public static VulnerabilitySeverity ToDbSeverity(this VulnTrack.Models.Severity sev) => sev switch
    {
        VulnTrack.Models.Severity.Critical => VulnerabilitySeverity.Critical,
        VulnTrack.Models.Severity.High => VulnerabilitySeverity.High,
        VulnTrack.Models.Severity.Medium => VulnerabilitySeverity.Medium,
        VulnTrack.Models.Severity.Low => VulnerabilitySeverity.Low,
        _ => VulnerabilitySeverity.Info
    };

    public static VulnTrack.Models.FindingStatus ToUiStatus(this VulnerabilityStatus st) => st switch
    {
        VulnerabilityStatus.Open => VulnTrack.Models.FindingStatus.Open,
        VulnerabilityStatus.InProgress => VulnTrack.Models.FindingStatus.InProgress,
        VulnerabilityStatus.FixedAwaitingVerification => VulnTrack.Models.FindingStatus.FixedAwaitingVerification,
        VulnerabilityStatus.Closed => VulnTrack.Models.FindingStatus.Closed,
        _ => VulnTrack.Models.FindingStatus.AcceptedRisk
    };

    public static VulnerabilityStatus ToDbStatus(this VulnTrack.Models.FindingStatus st) => st switch
    {
        VulnTrack.Models.FindingStatus.Open => VulnerabilityStatus.Open,
        VulnTrack.Models.FindingStatus.InProgress => VulnerabilityStatus.InProgress,
        VulnTrack.Models.FindingStatus.FixedAwaitingVerification => VulnerabilityStatus.FixedAwaitingVerification,
        VulnTrack.Models.FindingStatus.Closed => VulnerabilityStatus.Closed,
        _ => VulnerabilityStatus.AcceptedRisk
    };
}
