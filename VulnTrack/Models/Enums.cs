namespace VulnTrack.Models;

public enum Severity
{
    Critical,
    High,
    Medium,
    Low,
    Info
}

public enum FindingStatus
{
    Open,
    InProgress,
    FixedAwaitingVerification,
    Closed,
    AcceptedRisk
}

public enum BusinessImpact
{
    Critical,
    High,
    Medium,
    Low
}

public enum ToastKind
{
    Success,
    Info,
    Warning,
    Error
}

public enum RescanResult
{
    Pending,
    StillVulnerable,
    ConfirmedFixed
}

public enum AlertType
{
    CriticalImported,
    SlaOverdue,
    RescanResult,
    ImportFailed
}

public static class Roles
{
    public const string Administrator = "Administrator";
    public const string SecurityAnalyst = "Security Analyst";
    public const string AssetOwner = "Asset Owner";
}

public static class SlaPolicy
{
    public static int? DaysFor(Severity severity) => severity switch
    {
        Severity.Critical => 7,
        Severity.High => 14,
        Severity.Medium => 30,
        Severity.Low => 90,
        Severity.Info => null,
        _ => 30
    };
}

public static class Labels
{
    public static string ToLabel(this FindingStatus status) => status switch
    {
        FindingStatus.Open => "Open",
        FindingStatus.InProgress => "In Progress",
        FindingStatus.FixedAwaitingVerification => "Fixed, awaiting verification",
        FindingStatus.Closed => "Closed",
        FindingStatus.AcceptedRisk => "Accepted Risk",
        _ => status.ToString()
    };

    public static string CssKey(this FindingStatus status) => status switch
    {
        FindingStatus.Open => "open",
        FindingStatus.InProgress => "progress",
        FindingStatus.FixedAwaitingVerification => "fixed",
        FindingStatus.Closed => "closed",
        FindingStatus.AcceptedRisk => "accepted",
        _ => "open"
    };

    public static string CssKey(this Severity severity) => severity.ToString().ToLowerInvariant();
}

public record ChartSegment(string Label, double Value, string Color);

public record ChartSeries(string Name, IReadOnlyList<double> Values, string Color);
