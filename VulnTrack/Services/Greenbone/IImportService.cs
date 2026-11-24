using VulnTrack.Data.Entities;

namespace VulnTrack.Services.Greenbone;

public sealed record ImportOptions(
    bool AutoAssignOwners = true,
    bool ApplySlaDueDates = true,
    bool IncludeInfoLevel = false,
    ImportSource Source = ImportSource.ManualUpload,
    string IpAddress = "127.0.0.1"
);

public sealed record ImportProgress(int Percent, string Message);

public sealed record ImportPreview(
    int FindingCount,
    int UniqueFindingCount,
    int HostCount,
    int DuplicateCount,
    IReadOnlyList<string> Warnings
);

public sealed record ImportSummary(
    int BatchId,
    ImportStatus Status,
    int TotalFindings,
    int NewCount,
    int UpdatedCount,
    int MarkedForVerificationCount,
    int ReopenedCount,
    int ClosedCount,
    string ToastMessage
);

public interface IImportService
{
    Task<ImportPreview> PreviewAsync(
        Stream file,
        string fileName,
        ImportOptions options,
        CancellationToken ct = default);

    Task<ImportSummary> ImportAsync(
        Stream file,
        string fileName,
        string targetName,
        ImportOptions options,
        string userId,
        IProgress<ImportProgress>? progress = null,
        CancellationToken ct = default);

    Task RollbackImportAsync(
        int batchId,
        string userId,
        bool confirmed,
        string ipAddress = "127.0.0.1",
        CancellationToken ct = default);
}
