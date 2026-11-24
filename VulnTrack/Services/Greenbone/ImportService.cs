using Microsoft.EntityFrameworkCore;
using VulnTrack.Data;
using VulnTrack.Data.Entities;

namespace VulnTrack.Services.Greenbone;

public sealed class ImportService : IImportService
{
    private readonly IDbContextFactory<AppDbContext> _dbFactory;
    private readonly IGreenboneReportParser _parser;
    private readonly ILogger<ImportService> _logger;

    public ImportService(
        IDbContextFactory<AppDbContext> dbFactory,
        IGreenboneReportParser parser,
        ILogger<ImportService> logger)
    {
        _dbFactory = dbFactory;
        _parser = parser;
        _logger = logger;
    }

    public async Task<ImportPreview> PreviewAsync(
        Stream file,
        string fileName,
        ImportOptions options,
        CancellationToken ct = default)
    {
        var parsed = await ParseByExtensionAsync(file, fileName, options.IncludeInfoLevel, ct);
        var uniqueCount = parsed.Findings
            .GroupBy(f => (f.Hostname.ToLowerInvariant(), f.IpAddress.ToLowerInvariant(), f.CveId.ToUpperInvariant(), f.Port))
            .Count();
        var hostCount = parsed.Findings
            .Select(f => (f.Hostname.ToLowerInvariant(), f.IpAddress.ToLowerInvariant()))
            .Distinct()
            .Count();

        return new ImportPreview(
            FindingCount: parsed.Findings.Count,
            UniqueFindingCount: uniqueCount,
            HostCount: hostCount,
            DuplicateCount: Math.Max(0, parsed.Findings.Count - uniqueCount),
            Warnings: parsed.Warnings);
    }

    public async Task<ImportSummary> ImportAsync(
        Stream file,
        string fileName,
        string targetName,
        ImportOptions options,
        string userId,
        IProgress<ImportProgress>? progress = null,
        CancellationToken ct = default)
    {
        var startedAt = DateTime.UtcNow;
        _logger.LogInformation("Starting Greenbone import {FileName} (source: {Source}) by user {UserId}", fileName, options.Source, userId);
        progress?.Report(new ImportProgress(10, "Parsing scan report..."));

        try
        {
            var parseResult = await ParseByExtensionAsync(file, fileName, options.IncludeInfoLevel, ct);

            await using var db = await _dbFactory.CreateDbContextAsync(ct);
            await using var tx = await db.Database.BeginTransactionAsync(ct);

            // (a) Create ImportBatch (Status = Running)
            var batch = new ImportBatchEntity
            {
                Source = options.Source,
                FileName = fileName,
                TargetName = string.IsNullOrWhiteSpace(targetName) ? fileName : targetName,
                StartedAt = startedAt,
                Status = ImportStatus.Running,
                ImportedByUserId = userId
            };
            db.ImportBatches.Add(batch);
            await db.SaveChangesAsync(ct);

            progress?.Report(new ImportProgress(30, "Matching assets against registry..."));

            var now = DateTime.UtcNow;
            var slaMap = await db.SlaRules.AsNoTracking().ToDictionaryAsync(r => r.Severity, r => r.DueDays, ct);

            // Deduplicate incoming findings by (Hostname, IpAddress, CveId, Port)
            var deduped = parseResult.Findings
                .GroupBy(f => (Host: f.Hostname.ToLowerInvariant(), Ip: f.IpAddress.ToLowerInvariant(), Cve: f.CveId.ToUpperInvariant(), f.Port))
                .Select(g => g.OrderByDescending(x => x.CvssScore).First())
                .ToList();

            // (b) Find assets by Hostname + IpAddress, otherwise create (Criticality = Medium, no owner)
            var allAssets = await db.Assets.ToListAsync(ct);
            var assetMap = allAssets.ToDictionary(
                a => (a.Hostname.ToLowerInvariant(), a.IpAddress.ToLowerInvariant()));

            var scannedAssetIds = new HashSet<int>();
            foreach (var hostGroup in deduped.GroupBy(f => (f.Hostname.ToLowerInvariant(), f.IpAddress.ToLowerInvariant())))
            {
                var sample = hostGroup.First();
                if (!assetMap.TryGetValue(hostGroup.Key, out var asset))
                {
                    asset = new AssetEntity
                    {
                        Hostname = sample.Hostname,
                        IpAddress = sample.IpAddress,
                        OperatingSystem = "Detected via Greenbone",
                        Department = "Unassigned",
                        Criticality = AssetCriticality.Medium,
                        OwnerUserId = null,
                        IsActive = true,
                        CreatedAt = now,
                        LastScannedAt = now
                    };
                    db.Assets.Add(asset);
                    await db.SaveChangesAsync(ct);
                    assetMap[hostGroup.Key] = asset;
                }
                else
                {
                    asset.LastScannedAt = now;
                }
                scannedAssetIds.Add(asset.Id);
            }

            progress?.Report(new ImportProgress(55, "Merging findings and applying SLA rules..."));

            var existingVulns = await db.Vulnerabilities
                .Where(v => scannedAssetIds.Contains(v.AssetId))
                .ToListAsync(ct);

            var vulnMap = existingVulns.ToDictionary(v => (v.AssetId, v.CveId.ToUpperInvariant(), v.Port));
            var seenKeys = new HashSet<(int AssetId, string CveId, int Port)>();

            // (c) & (f) & (g) Process findings present in this scan
            foreach (var f in deduped)
            {
                ct.ThrowIfCancellationRequested();
                var asset = assetMap[(f.Hostname.ToLowerInvariant(), f.IpAddress.ToLowerInvariant())];
                var key = (asset.Id, f.CveId.ToUpperInvariant(), f.Port);
                seenKeys.Add(key);

                if (!vulnMap.TryGetValue(key, out var existing))
                {
                    var dueDays = options.ApplySlaDueDates && slaMap.TryGetValue(f.Severity, out var d) ? d : 30;
                    var created = new VulnerabilityEntity
                    {
                        CveId = f.CveId,
                        Title = f.Title,
                        Description = f.Description,
                        Severity = f.Severity,
                        CvssScore = f.CvssScore,
                        AssetId = asset.Id,
                        Port = f.Port,
                        Protocol = f.Protocol,
                        Service = f.Service,
                        BusinessImpact = asset.BusinessImpactNotes,
                        RecommendedFix = f.RecommendedFix,
                        OwnerUserId = options.AutoAssignOwners ? asset.OwnerUserId : null,
                        DueDate = now.Date.AddDays(dueDays),
                        Status = VulnerabilityStatus.Open,
                        DetectedAt = now,
                        LastSeenAt = now,
                        CreatedByImportBatchId = batch.Id,
                        LastImportBatchId = batch.Id
                    };

                    db.Vulnerabilities.Add(created);
                    await db.SaveChangesAsync(ct);

                    db.VulnerabilityHistory.Add(new VulnerabilityHistoryEntity
                    {
                        VulnerabilityId = created.Id,
                        ChangeType = VulnerabilityChangeType.Imported,
                        NewValue = "Open",
                        Note = $"Imported from {fileName} (NVT {f.NvtOid})",
                        ChangedByUserId = userId,
                        ImportBatchId = batch.Id,
                        ChangedAt = now
                    });

                    // (h) Alert for each new Critical finding
                    if (created.Severity == VulnerabilitySeverity.Critical)
                    {
                        db.Alerts.Add(new AlertEntity
                        {
                            Type = AlertEventType.CriticalFinding,
                            Message = $"Critical finding imported: {created.CveId} on {asset.Hostname} (port {created.Port}/{created.Protocol}).",
                            VulnerabilityId = created.Id,
                            RecipientUserId = created.OwnerUserId ?? userId,
                            CreatedAt = now
                        });
                    }

                    batch.NewCount++;
                    vulnMap[key] = created;
                }
                else
                {
                    // (g) AcceptedRisk findings are never changed automatically
                    if (existing.Status == VulnerabilityStatus.AcceptedRisk)
                    {
                        existing.LastSeenAt = now;
                        continue;
                    }

                    var changedNotes = new List<string>();
                    existing.LastSeenAt = now;
                    existing.LastImportBatchId = batch.Id;

                    if (existing.CvssScore != f.CvssScore)
                    {
                        changedNotes.Add($"CVSS {existing.CvssScore:0.0} -> {f.CvssScore:0.0}");
                        existing.CvssScore = f.CvssScore;
                    }
                    if (existing.Severity != f.Severity)
                    {
                        changedNotes.Add($"Severity {existing.Severity} -> {f.Severity}");
                        existing.Severity = f.Severity;
                    }

                    // (f) Closed or FixedAwaitingVerification present again -> Reopened (InProgress)
                    if (existing.Status is VulnerabilityStatus.Closed or VulnerabilityStatus.FixedAwaitingVerification)
                    {
                        var oldStatus = existing.Status.ToString();
                        existing.Status = VulnerabilityStatus.InProgress;
                        existing.FixedAt = null;
                        existing.ClosedAt = null;
                        existing.VerifiedByImportBatchId = null;
                        batch.ReopenedCount++;

                        db.VulnerabilityHistory.Add(new VulnerabilityHistoryEntity
                        {
                            VulnerabilityId = existing.Id,
                            ChangeType = VulnerabilityChangeType.Reopened,
                            OldValue = oldStatus,
                            NewValue = "InProgress",
                            Note = $"Finding reappeared in {fileName}; reopened.",
                            ChangedByUserId = userId,
                            ImportBatchId = batch.Id,
                            ChangedAt = now
                        });

                        // (h) Alert for each reopened finding
                        db.Alerts.Add(new AlertEntity
                        {
                            Type = AlertEventType.RescanResult,
                            Message = $"Reopened finding: {existing.CveId} still detected on {asset.Hostname}.",
                            VulnerabilityId = existing.Id,
                            RecipientUserId = existing.OwnerUserId ?? userId,
                            CreatedAt = now
                        });
                    }
                    else
                    {
                        batch.UpdatedCount++;
                        if (changedNotes.Count > 0)
                        {
                            db.VulnerabilityHistory.Add(new VulnerabilityHistoryEntity
                            {
                                VulnerabilityId = existing.Id,
                                ChangeType = VulnerabilityChangeType.Ranked,
                                NewValue = string.Join("; ", changedNotes),
                                Note = $"Updated from {fileName}",
                                ChangedByUserId = userId,
                                ImportBatchId = batch.Id,
                                ChangedAt = now
                            });
                        }
                    }
                }
            }

            progress?.Report(new ImportProgress(80, "Applying rescan verification rules..."));

            // (d), (e), (g) Absence pass on scanned assets
            foreach (var existing in existingVulns)
            {
                ct.ThrowIfCancellationRequested();
                if (existing.Status == VulnerabilityStatus.AcceptedRisk) continue;

                var key = (existing.AssetId, existing.CveId.ToUpperInvariant(), existing.Port);
                if (seenKeys.Contains(key)) continue;

                if (existing.Status is VulnerabilityStatus.Open or VulnerabilityStatus.InProgress)
                {
                    // (d) Absent Open/InProgress -> FixedAwaitingVerification (never straight to Closed)
                    var oldStatus = existing.Status.ToString();
                    existing.Status = VulnerabilityStatus.FixedAwaitingVerification;
                    existing.FixedAt = now;
                    existing.LastImportBatchId = batch.Id;
                    batch.MarkedForVerificationCount++;

                    db.VulnerabilityHistory.Add(new VulnerabilityHistoryEntity
                    {
                        VulnerabilityId = existing.Id,
                        ChangeType = VulnerabilityChangeType.StatusChanged,
                        OldValue = oldStatus,
                        NewValue = "FixedAwaitingVerification",
                        Note = $"Not present in {fileName}; moved to Fixed, awaiting verification.",
                        ChangedByUserId = userId,
                        ImportBatchId = batch.Id,
                        ChangedAt = now
                    });
                }
                else if (existing.Status == VulnerabilityStatus.FixedAwaitingVerification)
                {
                    // (e) Absent FixedAwaitingVerification -> Closed with VerifiedByImportBatchId
                    existing.Status = VulnerabilityStatus.Closed;
                    existing.ClosedAt = now;
                    existing.VerifiedByImportBatchId = batch.Id;
                    existing.LastImportBatchId = batch.Id;
                    batch.ClosedCount++;

                    db.VulnerabilityHistory.Add(new VulnerabilityHistoryEntity
                    {
                        VulnerabilityId = existing.Id,
                        ChangeType = VulnerabilityChangeType.RescanVerified,
                        OldValue = "FixedAwaitingVerification",
                        NewValue = "Verified",
                        Note = $"Verified absent in rescan {fileName}.",
                        ImportBatchId = batch.Id,
                        ChangedAt = now
                    });
                    db.VulnerabilityHistory.Add(new VulnerabilityHistoryEntity
                    {
                        VulnerabilityId = existing.Id,
                        ChangeType = VulnerabilityChangeType.Closed,
                        OldValue = "FixedAwaitingVerification",
                        NewValue = "Closed",
                        Note = $"Closed after rescan verification (batch #{batch.Id}).",
                        ChangedByUserId = userId,
                        ImportBatchId = batch.Id,
                        ChangedAt = now
                    });
                }
            }

            // (i) Complete batch + AuditLogs row
            batch.TotalFindings = deduped.Count;
            batch.CompletedAt = DateTime.UtcNow;
            batch.Status = parseResult.Warnings.Count > 0 ? ImportStatus.CompletedWithWarnings : ImportStatus.Completed;
            if (parseResult.Warnings.Count > 0)
            {
                batch.ErrorMessage = string.Join(" | ", parseResult.Warnings.Take(5));
            }

            db.AuditLogs.Add(new AuditLogEntity
            {
                UserId = userId,
                Action = "ImportCompleted",
                TargetType = "ImportBatch",
                TargetId = batch.Id.ToString(),
                Details = $"{fileName}: {batch.NewCount} new, {batch.UpdatedCount} updated, {batch.MarkedForVerificationCount} marked for verification, {batch.ClosedCount} closed, {batch.ReopenedCount} reopened",
                IpAddress = options.IpAddress,
                Timestamp = DateTime.UtcNow
            });

            await db.SaveChangesAsync(ct);
            await tx.CommitAsync(ct);

            progress?.Report(new ImportProgress(100, "Import complete."));

            var toast = $"{batch.NewCount} new, {batch.UpdatedCount} updated, {batch.MarkedForVerificationCount} marked for verification, {batch.ClosedCount} closed"
                        + (batch.ReopenedCount > 0 ? $", {batch.ReopenedCount} reopened" : "");

            _logger.LogInformation("Completed import batch #{BatchId}: {Summary}", batch.Id, toast);

            return new ImportSummary(
                batch.Id,
                batch.Status,
                batch.TotalFindings,
                batch.NewCount,
                batch.UpdatedCount,
                batch.MarkedForVerificationCount,
                batch.ReopenedCount,
                batch.ClosedCount,
                toast);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Greenbone import failed for {FileName}", fileName);

            // Persist a Failed batch outside the rolled-back transaction
            await using var errDb = await _dbFactory.CreateDbContextAsync(CancellationToken.None);
            var failed = new ImportBatchEntity
            {
                Source = options.Source,
                FileName = fileName,
                TargetName = string.IsNullOrWhiteSpace(targetName) ? fileName : targetName,
                StartedAt = startedAt,
                CompletedAt = DateTime.UtcNow,
                Status = ImportStatus.Failed,
                ErrorMessage = ex.Message.Length > 2000 ? ex.Message[..2000] : ex.Message,
                ImportedByUserId = userId
            };
            errDb.ImportBatches.Add(failed);
            errDb.AuditLogs.Add(new AuditLogEntity
            {
                UserId = userId,
                Action = "ImportFailed",
                TargetType = "ImportBatch",
                TargetId = fileName,
                Details = failed.ErrorMessage,
                IpAddress = options.IpAddress,
                Timestamp = DateTime.UtcNow
            });
            await errDb.SaveChangesAsync(CancellationToken.None);
            throw;
        }
    }

    public async Task RollbackImportAsync(
        int batchId,
        string userId,
        bool confirmed,
        string ipAddress = "127.0.0.1",
        CancellationToken ct = default)
    {
        if (!confirmed)
            throw new InvalidOperationException("Rollback requires explicit confirmation.");

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        await using var tx = await db.Database.BeginTransactionAsync(ct);

        var batch = await db.ImportBatches.FirstOrDefaultAsync(b => b.Id == batchId, ct)
                    ?? throw new KeyNotFoundException($"Import batch #{batchId} not found.");

        if (batch.Status == ImportStatus.RolledBack) return;

        // Restore status changes on pre-existing findings from history rows
        var historyRows = await db.VulnerabilityHistory
            .Include(h => h.Vulnerability)
            .Where(h => h.ImportBatchId == batchId && h.Vulnerability.CreatedByImportBatchId != batchId)
            .OrderByDescending(h => h.ChangedAt)
            .ToListAsync(ct);

        foreach (var h in historyRows)
        {
            if (Enum.TryParse<VulnerabilityStatus>(h.OldValue, out var prior))
            {
                h.Vulnerability.Status = prior;
                if (prior != VulnerabilityStatus.Closed)
                {
                    h.Vulnerability.ClosedAt = null;
                    h.Vulnerability.VerifiedByImportBatchId = null;
                }
                if (prior is VulnerabilityStatus.Open or VulnerabilityStatus.InProgress)
                {
                    h.Vulnerability.FixedAt = null;
                }
            }
        }

        // Remove findings created by this batch (after clearing dependent alerts and history)
        var created = await db.Vulnerabilities.Where(v => v.CreatedByImportBatchId == batchId).ToListAsync(ct);
        var createdIds = created.Select(v => v.Id).ToList();

        if (createdIds.Count > 0)
        {
            var alerts = await db.Alerts.Where(a => a.VulnerabilityId.HasValue && createdIds.Contains(a.VulnerabilityId.Value)).ToListAsync(ct);
            var createdHist = await db.VulnerabilityHistory.Where(h => createdIds.Contains(h.VulnerabilityId)).ToListAsync(ct);
            db.Alerts.RemoveRange(alerts);
            db.VulnerabilityHistory.RemoveRange(createdHist);
            db.Vulnerabilities.RemoveRange(created);
        }

        batch.Status = ImportStatus.RolledBack;
        db.AuditLogs.Add(new AuditLogEntity
        {
            UserId = userId,
            Action = "ImportRolledBack",
            TargetType = "ImportBatch",
            TargetId = batchId.ToString(),
            Details = $"Rolled back {batch.FileName}: removed {createdIds.Count} created findings, restored {historyRows.Count} history transitions.",
            IpAddress = ipAddress,
            Timestamp = DateTime.UtcNow
        });

        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        _logger.LogInformation("Rolled back import batch #{BatchId} by user {UserId}", batchId, userId);
    }

    private Task<ParseResult> ParseByExtensionAsync(Stream file, string fileName, bool includeInfo, CancellationToken ct)
    {
        var ext = Path.GetExtension(fileName).ToLowerInvariant();
        return ext switch
        {
            ".xml" => _parser.ParseXmlAsync(file, includeInfo, ct),
            ".csv" => _parser.ParseCsvAsync(file, includeInfo, ct),
            _ => throw new InvalidDataException($"Unsupported file format '{ext}'. Upload a Greenbone .xml or .csv export.")
        };
    }
}
