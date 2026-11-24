using Microsoft.AspNetCore.Identity;

namespace VulnTrack.Data.Entities;

public class ApplicationUser : IdentityUser
{
    public string FullName { get; set; } = string.Empty;
    public string Department { get; set; } = string.Empty;
    public bool IsActive { get; set; } = true;
    public DateTime? LastLoginAt { get; set; }

    public ICollection<AssetEntity> OwnedAssets { get; set; } = new List<AssetEntity>();
    public ICollection<VulnerabilityEntity> OwnedVulnerabilities { get; set; } = new List<VulnerabilityEntity>();
}

public class AssetEntity
{
    public int Id { get; set; }
    public string Hostname { get; set; } = string.Empty;
    public string IpAddress { get; set; } = string.Empty;
    public string OperatingSystem { get; set; } = string.Empty;
    public string Department { get; set; } = string.Empty;
    public AssetCriticality Criticality { get; set; } = AssetCriticality.Medium;
    public string? OwnerUserId { get; set; }
    public string? BusinessImpactNotes { get; set; }
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastScannedAt { get; set; }

    public ApplicationUser? Owner { get; set; }
    public ICollection<VulnerabilityEntity> Vulnerabilities { get; set; } = new List<VulnerabilityEntity>();
}

public class ImportBatchEntity
{
    public int Id { get; set; }
    public ImportSource Source { get; set; }
    public string FileName { get; set; } = string.Empty;
    public string TargetName { get; set; } = string.Empty;
    public DateTime StartedAt { get; set; } = DateTime.UtcNow;
    public DateTime? CompletedAt { get; set; }
    public ImportStatus Status { get; set; } = ImportStatus.Running;
    public int TotalFindings { get; set; }
    public int NewCount { get; set; }
    public int UpdatedCount { get; set; }
    public int MarkedForVerificationCount { get; set; }
    public int ReopenedCount { get; set; }
    public int ClosedCount { get; set; }
    public string? ErrorMessage { get; set; }
    public string ImportedByUserId { get; set; } = string.Empty;

    public ApplicationUser ImportedBy { get; set; } = default!;
}

public class VulnerabilityEntity
{
    public int Id { get; set; }
    public string CveId { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string? Description { get; set; }
    public VulnerabilitySeverity Severity { get; set; }
    public decimal CvssScore { get; set; }
    public int AssetId { get; set; }
    public int Port { get; set; }
    public string Protocol { get; set; } = "tcp";
    public string? Service { get; set; }
    public string? BusinessImpact { get; set; }
    public string? RecommendedFix { get; set; }
    public string? OwnerUserId { get; set; }
    public DateTime DueDate { get; set; }
    public VulnerabilityStatus Status { get; set; } = VulnerabilityStatus.Open;
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    public DateTime LastSeenAt { get; set; } = DateTime.UtcNow;
    public DateTime? FixedAt { get; set; }
    public DateTime? ClosedAt { get; set; }
    public int? CreatedByImportBatchId { get; set; }
    public int? LastImportBatchId { get; set; }
    public int? VerifiedByImportBatchId { get; set; }
    public byte[] RowVersion { get; set; } = new byte[] { 1 };

    public AssetEntity Asset { get; set; } = default!;
    public ApplicationUser? Owner { get; set; }
    public ImportBatchEntity? CreatedByImportBatch { get; set; }
    public ImportBatchEntity? LastImportBatch { get; set; }
    public ImportBatchEntity? VerifiedByImportBatch { get; set; }
    public ICollection<VulnerabilityHistoryEntity> History { get; set; } = new List<VulnerabilityHistoryEntity>();

    public bool IsOverdueUtc(DateTime utcNow) =>
        Status is not (VulnerabilityStatus.Closed or VulnerabilityStatus.AcceptedRisk) && DueDate < utcNow;

    public int DaysOverdueUtc(DateTime utcNow) =>
        IsOverdueUtc(utcNow) ? Math.Max(1, (int)(utcNow.Date - DueDate.Date).TotalDays) : 0;
}

public class VulnerabilityHistoryEntity
{
    public int Id { get; set; }
    public int VulnerabilityId { get; set; }
    public VulnerabilityChangeType ChangeType { get; set; }
    public string? OldValue { get; set; }
    public string? NewValue { get; set; }
    public string? Note { get; set; }
    public string? ChangedByUserId { get; set; }
    public int? ImportBatchId { get; set; }
    public DateTime ChangedAt { get; set; } = DateTime.UtcNow;

    public VulnerabilityEntity Vulnerability { get; set; } = default!;
    public ApplicationUser? ChangedBy { get; set; }
    public ImportBatchEntity? ImportBatch { get; set; }
}

public class SlaRuleEntity
{
    public int Id { get; set; }
    public VulnerabilitySeverity Severity { get; set; }
    public int DueDays { get; set; }
}

public class AlertEntity
{
    public int Id { get; set; }
    public AlertEventType Type { get; set; }
    public string Message { get; set; } = string.Empty;
    public int? VulnerabilityId { get; set; }
    public string RecipientUserId { get; set; } = string.Empty;
    public bool IsRead { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public VulnerabilityEntity? Vulnerability { get; set; }
    public ApplicationUser Recipient { get; set; } = default!;
}

public class AuditLogEntity
{
    public int Id { get; set; }
    public string? UserId { get; set; }
    public string Action { get; set; } = string.Empty;
    public string TargetType { get; set; } = string.Empty;
    public string TargetId { get; set; } = string.Empty;
    public string? Details { get; set; }
    public string IpAddress { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    public ApplicationUser? User { get; set; }
}

public class ReportRecordEntity
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public ReportFileFormat Format { get; set; }
    public string? FiltersJson { get; set; }
    public string CreatedByUserId { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public string? FilePath { get; set; }

    public ApplicationUser CreatedBy { get; set; } = default!;
}

public class AppSettingEntity
{
    public string Key { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
    public bool IsEncrypted { get; set; }
    public string? Description { get; set; }
    public string? UpdatedByUserId { get; set; }
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    public ApplicationUser? UpdatedBy { get; set; }
}
