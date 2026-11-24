using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using VulnTrack.Data.Entities;

namespace VulnTrack.Data;

public class AppDbContext : IdentityDbContext<ApplicationUser>
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<AssetEntity> Assets => Set<AssetEntity>();
    public DbSet<ImportBatchEntity> ImportBatches => Set<ImportBatchEntity>();
    public DbSet<VulnerabilityEntity> Vulnerabilities => Set<VulnerabilityEntity>();
    public DbSet<VulnerabilityHistoryEntity> VulnerabilityHistory => Set<VulnerabilityHistoryEntity>();
    public DbSet<SlaRuleEntity> SlaRules => Set<SlaRuleEntity>();
    public DbSet<AlertEntity> Alerts => Set<AlertEntity>();
    public DbSet<AuditLogEntity> AuditLogs => Set<AuditLogEntity>();
    public DbSet<ReportRecordEntity> ReportRecords => Set<ReportRecordEntity>();
    public DbSet<AppSettingEntity> AppSettings => Set<AppSettingEntity>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        base.OnModelCreating(b);
        var utcNowSql = Database.IsSqlServer() ? "SYSUTCDATETIME()" : "CURRENT_TIMESTAMP";

        b.Entity<ApplicationUser>(e =>
        {
            e.Property(x => x.FullName).HasMaxLength(120).IsRequired();
            e.Property(x => x.Department).HasMaxLength(100).IsRequired();
            e.Property(x => x.IsActive).HasDefaultValue(true);
            e.Property(x => x.LastLoginAt).HasColumnType("datetime2(0)");
        });

        b.Entity<AssetEntity>(e =>
        {
            e.ToTable("Assets", t => t.HasCheckConstraint("CK_Assets_Criticality", "[Criticality] BETWEEN 1 AND 3"));
            e.HasKey(x => x.Id);
            e.Property(x => x.Hostname).HasMaxLength(128).IsRequired();
            e.Property(x => x.IpAddress).HasMaxLength(45).IsRequired();
            e.Property(x => x.OperatingSystem).HasMaxLength(128).IsRequired();
            e.Property(x => x.Department).HasMaxLength(100).IsRequired();
            e.Property(x => x.Criticality).HasConversion<byte>();
            e.Property(x => x.BusinessImpactNotes).HasMaxLength(1000);
            e.Property(x => x.IsActive).HasDefaultValue(true);
            e.Property(x => x.CreatedAt).HasColumnType("datetime2(0)").HasDefaultValueSql(utcNowSql);
            e.Property(x => x.LastScannedAt).HasColumnType("datetime2(0)");

            e.HasIndex(x => new { x.Hostname, x.IpAddress }).IsUnique().HasDatabaseName("UQ_Assets_Hostname_IpAddress");
            e.HasIndex(x => x.OwnerUserId).HasDatabaseName("IX_Assets_OwnerUserId");

            e.HasOne(x => x.Owner)
                .WithMany(u => u.OwnedAssets)
                .HasForeignKey(x => x.OwnerUserId)
                .IsRequired(false)
                .HasConstraintName("FK_Assets_AspNetUsers")
                .OnDelete(DeleteBehavior.Restrict);
        });

        b.Entity<ImportBatchEntity>(e =>
        {
            e.ToTable("ImportBatches", t =>
            {
                t.HasCheckConstraint("CK_ImportBatches_Source", "[Source] IN (1, 2)");
                t.HasCheckConstraint("CK_ImportBatches_Status", "[Status] BETWEEN 1 AND 5");
            });
            e.HasKey(x => x.Id);
            e.Property(x => x.Source).HasConversion<byte>();
            e.Property(x => x.Status).HasConversion<byte>().HasDefaultValue(ImportStatus.Running);
            e.Property(x => x.FileName).HasMaxLength(260).IsRequired();
            e.Property(x => x.TargetName).HasMaxLength(160).IsRequired();
            e.Property(x => x.ErrorMessage).HasMaxLength(2000);
            e.Property(x => x.StartedAt).HasColumnType("datetime2(0)").HasDefaultValueSql(utcNowSql);
            e.Property(x => x.CompletedAt).HasColumnType("datetime2(0)");

            e.HasIndex(x => x.StartedAt).IsDescending().HasDatabaseName("IX_ImportBatches_StartedAt");
            e.HasOne(x => x.ImportedBy)
                .WithMany()
                .HasForeignKey(x => x.ImportedByUserId)
                .HasConstraintName("FK_ImportBatches_AspNetUsers")
                .OnDelete(DeleteBehavior.Restrict);
        });

        b.Entity<VulnerabilityEntity>(e =>
        {
            e.ToTable("Vulnerabilities", t =>
            {
                t.HasCheckConstraint("CK_Vulnerabilities_Severity", "[Severity] BETWEEN 1 AND 5");
                t.HasCheckConstraint("CK_Vulnerabilities_CvssScore", "[CvssScore] >= 0.0 AND [CvssScore] <= 10.0");
                t.HasCheckConstraint("CK_Vulnerabilities_Port", "[Port] >= 0 AND [Port] <= 65535");
                t.HasCheckConstraint("CK_Vulnerabilities_Status", "[Status] BETWEEN 1 AND 5");
                t.HasCheckConstraint("CK_Vulnerabilities_ClosedRequiresRescan",
                    "[Status] <> 4 OR ([VerifiedByImportBatchId] IS NOT NULL AND [ClosedAt] IS NOT NULL)");
            });
            e.HasKey(x => x.Id);
            e.Property(x => x.CveId).HasMaxLength(32).IsRequired();
            e.Property(x => x.Title).HasMaxLength(250).IsRequired();
            e.Property(x => x.Severity).HasConversion<byte>();
            e.Property(x => x.CvssScore).HasColumnType("decimal(3,1)");
            e.Property(x => x.Protocol).HasMaxLength(16).HasDefaultValue("tcp");
            e.Property(x => x.Service).HasMaxLength(100);
            e.Property(x => x.BusinessImpact).HasMaxLength(500);
            e.Property(x => x.Status).HasConversion<byte>().HasDefaultValue(VulnerabilityStatus.Open);
            e.Property(x => x.DueDate).HasColumnType("datetime2(0)");
            e.Property(x => x.DetectedAt).HasColumnType("datetime2(0)").HasDefaultValueSql(utcNowSql);
            e.Property(x => x.LastSeenAt).HasColumnType("datetime2(0)").HasDefaultValueSql(utcNowSql);
            e.Property(x => x.FixedAt).HasColumnType("datetime2(0)");
            e.Property(x => x.ClosedAt).HasColumnType("datetime2(0)");
            if (Database.IsSqlServer())
            {
                e.Property(x => x.RowVersion).IsRowVersion();
            }
            else
            {
                e.Property(x => x.RowVersion).IsConcurrencyToken();
            }

            e.HasIndex(x => new { x.CveId, x.AssetId, x.Port }).IsUnique().HasDatabaseName("UQ_Vulnerabilities_CveId_AssetId_Port");
            e.HasIndex(x => new { x.Status, x.Severity }).HasDatabaseName("IX_Vulnerabilities_Status_Severity");
            e.HasIndex(x => new { x.OwnerUserId, x.Status }).HasDatabaseName("IX_Vulnerabilities_OwnerUserId_Status");
            e.HasIndex(x => x.DueDate).HasDatabaseName("IX_Vulnerabilities_DueDate");
            e.HasIndex(x => x.AssetId).HasDatabaseName("IX_Vulnerabilities_AssetId");

            e.HasOne(x => x.Asset).WithMany(a => a.Vulnerabilities)
                .HasForeignKey(x => x.AssetId).HasConstraintName("FK_Vulnerabilities_Assets").OnDelete(DeleteBehavior.Restrict);
            e.HasOne(x => x.Owner).WithMany(u => u.OwnedVulnerabilities)
                .HasForeignKey(x => x.OwnerUserId).HasConstraintName("FK_Vulnerabilities_AspNetUsers").OnDelete(DeleteBehavior.Restrict);
            e.HasOne(x => x.CreatedByImportBatch).WithMany()
                .HasForeignKey(x => x.CreatedByImportBatchId).HasConstraintName("FK_Vulnerabilities_ImportBatches_CreatedBy").OnDelete(DeleteBehavior.Restrict);
            e.HasOne(x => x.LastImportBatch).WithMany()
                .HasForeignKey(x => x.LastImportBatchId).HasConstraintName("FK_Vulnerabilities_ImportBatches_LastSeen").OnDelete(DeleteBehavior.Restrict);
            e.HasOne(x => x.VerifiedByImportBatch).WithMany()
                .HasForeignKey(x => x.VerifiedByImportBatchId).HasConstraintName("FK_Vulnerabilities_ImportBatches_VerifiedBy").OnDelete(DeleteBehavior.Restrict);
        });

        b.Entity<VulnerabilityHistoryEntity>(e =>
        {
            e.ToTable("VulnerabilityHistory", t => t.HasCheckConstraint("CK_VulnerabilityHistory_ChangeType", "[ChangeType] BETWEEN 1 AND 9"));
            e.HasKey(x => x.Id);
            e.Property(x => x.ChangeType).HasConversion<byte>();
            e.Property(x => x.OldValue).HasMaxLength(500);
            e.Property(x => x.NewValue).HasMaxLength(500);
            e.Property(x => x.Note).HasMaxLength(1000);
            e.Property(x => x.ChangedAt).HasColumnType("datetime2(0)").HasDefaultValueSql(utcNowSql);

            e.HasIndex(x => new { x.VulnerabilityId, x.ChangedAt })
                .IsDescending(false, true)
                .HasDatabaseName("IX_VulnerabilityHistory_VulnerabilityId_ChangedAt");
            e.HasIndex(x => x.ImportBatchId).HasFilter("[ImportBatchId] IS NOT NULL").HasDatabaseName("IX_VulnerabilityHistory_ImportBatchId");

            e.HasOne(x => x.Vulnerability).WithMany(v => v.History)
                .HasForeignKey(x => x.VulnerabilityId).HasConstraintName("FK_VulnerabilityHistory_Vulnerabilities").OnDelete(DeleteBehavior.Restrict);
            e.HasOne(x => x.ChangedBy).WithMany()
                .HasForeignKey(x => x.ChangedByUserId).HasConstraintName("FK_VulnerabilityHistory_AspNetUsers").OnDelete(DeleteBehavior.Restrict);
            e.HasOne(x => x.ImportBatch).WithMany()
                .HasForeignKey(x => x.ImportBatchId).HasConstraintName("FK_VulnerabilityHistory_ImportBatches").OnDelete(DeleteBehavior.Restrict);
        });

        b.Entity<SlaRuleEntity>(e =>
        {
            e.ToTable("SlaRules", t =>
            {
                t.HasCheckConstraint("CK_SlaRules_Severity", "[Severity] BETWEEN 1 AND 5");
                t.HasCheckConstraint("CK_SlaRules_DueDays", "[DueDays] > 0");
            });
            e.HasKey(x => x.Id);
            e.Property(x => x.Severity).HasConversion<byte>();
            e.HasIndex(x => x.Severity).IsUnique().HasDatabaseName("UQ_SlaRules_Severity");
        });

        b.Entity<AlertEntity>(e =>
        {
            e.ToTable("Alerts", t => t.HasCheckConstraint("CK_Alerts_Type", "[Type] BETWEEN 1 AND 4"));
            e.HasKey(x => x.Id);
            e.Property(x => x.Type).HasConversion<byte>();
            e.Property(x => x.Message).HasMaxLength(500).IsRequired();
            e.Property(x => x.CreatedAt).HasColumnType("datetime2(0)").HasDefaultValueSql(utcNowSql);

            e.HasIndex(x => new { x.RecipientUserId, x.IsRead }).HasDatabaseName("IX_Alerts_RecipientUserId_IsRead");
            e.HasOne(x => x.Vulnerability).WithMany()
                .HasForeignKey(x => x.VulnerabilityId).HasConstraintName("FK_Alerts_Vulnerabilities").OnDelete(DeleteBehavior.Restrict);
            e.HasOne(x => x.Recipient).WithMany()
                .HasForeignKey(x => x.RecipientUserId).HasConstraintName("FK_Alerts_AspNetUsers").OnDelete(DeleteBehavior.Restrict);
        });

        b.Entity<AuditLogEntity>(e =>
        {
            e.ToTable("AuditLogs");
            e.HasKey(x => x.Id);
            e.Property(x => x.Action).HasMaxLength(100).IsRequired();
            e.Property(x => x.TargetType).HasMaxLength(60).IsRequired();
            e.Property(x => x.TargetId).HasMaxLength(64).IsRequired();
            e.Property(x => x.Details).HasMaxLength(1000);
            e.Property(x => x.IpAddress).HasMaxLength(45).IsRequired();
            e.Property(x => x.Timestamp).HasColumnType("datetime2(0)").HasDefaultValueSql(utcNowSql);

            e.HasIndex(x => x.Timestamp).IsDescending().HasDatabaseName("IX_AuditLogs_Timestamp");
            e.HasOne(x => x.User).WithMany()
                .HasForeignKey(x => x.UserId).HasConstraintName("FK_AuditLogs_AspNetUsers").OnDelete(DeleteBehavior.Restrict);
        });

        b.Entity<ReportRecordEntity>(e =>
        {
            e.ToTable("ReportRecords", t => t.HasCheckConstraint("CK_ReportRecords_Format", "[Format] IN (1, 2)"));
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(200).IsRequired();
            e.Property(x => x.Type).HasMaxLength(60).IsRequired();
            e.Property(x => x.Format).HasConversion<byte>();
            e.Property(x => x.CreatedAt).HasColumnType("datetime2(0)").HasDefaultValueSql(utcNowSql);
            e.Property(x => x.FilePath).HasMaxLength(400);

            e.HasOne(x => x.CreatedBy).WithMany()
                .HasForeignKey(x => x.CreatedByUserId).HasConstraintName("FK_ReportRecords_AspNetUsers").OnDelete(DeleteBehavior.Restrict);
        });

        b.Entity<AppSettingEntity>(e =>
        {
            e.ToTable("AppSettings");
            e.HasKey(x => x.Key);
            e.Property(x => x.Key).HasMaxLength(100);
            e.Property(x => x.Value).HasMaxLength(2000).IsRequired();
            e.Property(x => x.Description).HasMaxLength(250);
            e.Property(x => x.UpdatedAt).HasColumnType("datetime2(0)").HasDefaultValueSql(utcNowSql);

            e.HasOne(x => x.UpdatedBy).WithMany()
                .HasForeignKey(x => x.UpdatedByUserId).HasConstraintName("FK_AppSettings_AspNetUsers").OnDelete(DeleteBehavior.Restrict);
        });
    }
}
