using VulnTrack.Data.Entities;

namespace VulnTrack.Services.Greenbone;

public sealed record ParsedFinding(
    string CveId,
    string Title,
    string Description,
    VulnerabilitySeverity Severity,
    decimal CvssScore,
    string Hostname,
    string IpAddress,
    int Port,
    string Protocol,
    string Service,
    string RecommendedFix,
    string NvtOid
);

public sealed record ParseResult(
    IReadOnlyList<ParsedFinding> Findings,
    IReadOnlyList<string> Warnings
);

public interface IGreenboneReportParser
{
    Task<ParseResult> ParseXmlAsync(Stream xmlStream, bool includeInfoLevel, CancellationToken ct = default);
    Task<ParseResult> ParseCsvAsync(Stream csvStream, bool includeInfoLevel, CancellationToken ct = default);
}
