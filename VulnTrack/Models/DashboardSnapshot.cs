namespace VulnTrack.Models;

public record DashboardSnapshot(
    int TotalOpen,
    int Critical,
    int Overdue,
    int ClosedThisMonth,
    int CriticalOlderThan7,
    IReadOnlyDictionary<Severity, int> SeverityCounts,
    IReadOnlyDictionary<FindingStatus, int> StatusCounts,
    IReadOnlyList<string> WeekLabels,
    IReadOnlyList<double> OpenedWeekly,
    IReadOnlyList<double> ClosedWeekly,
    IReadOnlyList<double> TotalOpenTrend,
    IReadOnlyList<double> CriticalTrend,
    IReadOnlyList<double> OverdueTrend,
    IReadOnlyList<double> ClosedTrend,
    string TotalOpenDelta,
    bool TotalOpenDeltaGood,
    string CriticalDelta,
    bool CriticalDeltaGood,
    string OverdueDelta,
    bool OverdueDeltaGood,
    string ClosedDelta,
    bool ClosedDeltaGood
);
