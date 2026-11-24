using Microsoft.EntityFrameworkCore;
using VulnTrack.Data;
using VulnTrack.Data.Entities;

namespace VulnTrack.Services;

public class VulnTrackDataService
{
    private readonly IDbContextFactory<AppDbContext> _dbFactory;

    public VulnTrackDataService(IDbContextFactory<AppDbContext> dbFactory)
    {
        _dbFactory = dbFactory;
    }

    public async Task<List<VulnerabilityEntity>> GetVulnerabilitiesAsync(string? userId, bool isAssetOwner)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var query = db.Vulnerabilities
            .Include(v => v.Asset)
            .Include(v => v.Owner)
            .Include(v => v.LastImportBatch)
            .Include(v => v.VerifiedByImportBatch)
            .AsNoTracking();

        if (isAssetOwner && !string.IsNullOrEmpty(userId))
        {
            query = query.Where(v => v.OwnerUserId == userId);
        }

        return await query
            .OrderByDescending(v => v.Severity)
            .ThenByDescending(v => v.CvssScore)
            .ToListAsync();
    }

    public async Task<VulnerabilityEntity?> GetVulnerabilityDetailAsync(string cveOrId)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var query = db.Vulnerabilities
            .Include(v => v.Asset)
            .Include(v => v.Owner)
            .Include(v => v.LastImportBatch)
            .Include(v => v.VerifiedByImportBatch)
            .Include(v => v.History).ThenInclude(h => h.ChangedBy)
            .Include(v => v.History).ThenInclude(h => h.ImportBatch)
            .AsNoTracking();

        if (int.TryParse(cveOrId, out var id))
        {
            return await query.FirstOrDefaultAsync(v => v.Id == id);
        }

        return await query.FirstOrDefaultAsync(v => v.CveId == cveOrId);
    }

    public async Task<List<ApplicationUser>> GetActiveUsersAsync()
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        return await db.Users.Where(u => u.IsActive).OrderBy(u => u.FullName).AsNoTracking().ToListAsync();
    }

    public async Task<List<ImportBatchEntity>> GetImportBatchesAsync()
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        return await db.ImportBatches
            .Include(b => b.ImportedBy)
            .OrderByDescending(b => b.StartedAt)
            .AsNoTracking()
            .ToListAsync();
    }

    public async Task UpdateOwnerAsync(int vulnId, string? newOwnerId, string actorUserId, string ip = "127.0.0.1")
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var v = await db.Vulnerabilities.Include(x => x.Owner).FirstOrDefaultAsync(x => x.Id == vulnId);
        if (v is null) return;

        var oldName = v.Owner?.FullName ?? "Unassigned";
        var newOwner = string.IsNullOrEmpty(newOwnerId) ? null : await db.Users.FindAsync(newOwnerId);
        v.OwnerUserId = newOwner?.Id;

        db.VulnerabilityHistory.Add(new VulnerabilityHistoryEntity
        {
            VulnerabilityId = v.Id,
            ChangeType = VulnerabilityChangeType.OwnerAssigned,
            OldValue = oldName,
            NewValue = newOwner?.FullName ?? "Unassigned",
            Note = "Owner updated from console",
            ChangedByUserId = actorUserId,
            ChangedAt = DateTime.UtcNow
        });

        db.AuditLogs.Add(new AuditLogEntity
        {
            UserId = actorUserId,
            Action = "OwnerAssigned",
            TargetType = "Vulnerability",
            TargetId = v.Id.ToString(),
            Details = $"Assigned {v.CveId} from {oldName} to {newOwner?.FullName ?? "Unassigned"}",
            IpAddress = ip,
            Timestamp = DateTime.UtcNow
        });

        await db.SaveChangesAsync();
    }

    public async Task UpdateDueDateAsync(int vulnId, DateTime newDueUtc, string actorUserId, string ip = "127.0.0.1")
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var v = await db.Vulnerabilities.FindAsync(vulnId);
        if (v is null) return;

        var oldDue = v.DueDate.ToString("yyyy-MM-dd");
        v.DueDate = newDueUtc;

        db.VulnerabilityHistory.Add(new VulnerabilityHistoryEntity
        {
            VulnerabilityId = v.Id,
            ChangeType = VulnerabilityChangeType.DueDateChanged,
            OldValue = oldDue,
            NewValue = newDueUtc.ToString("yyyy-MM-dd"),
            Note = "SLA due date updated",
            ChangedByUserId = actorUserId,
            ChangedAt = DateTime.UtcNow
        });

        db.AuditLogs.Add(new AuditLogEntity
        {
            UserId = actorUserId,
            Action = "DueDateChanged",
            TargetType = "Vulnerability",
            TargetId = v.Id.ToString(),
            Details = $"Changed due date on {v.CveId} from {oldDue} to {newDueUtc:yyyy-MM-dd}",
            IpAddress = ip,
            Timestamp = DateTime.UtcNow
        });

        await db.SaveChangesAsync();
    }

    public async Task<(bool Ok, string Message)> UpdateStatusAsync(int vulnId, VulnerabilityStatus nextStatus, string actorUserId, string ip = "127.0.0.1")
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var v = await db.Vulnerabilities.FindAsync(vulnId);
        if (v is null) return (false, "Finding not found.");

        if (nextStatus == VulnerabilityStatus.Closed && v.VerifiedByImportBatchId is null)
        {
            return (false, "Closing is only possible after a verified Greenbone rescan confirms the fix.");
        }

        var old = v.Status.ToString();
        v.Status = nextStatus;
        if (nextStatus == VulnerabilityStatus.FixedAwaitingVerification)
        {
            v.FixedAt = DateTime.UtcNow;
        }
        else if (nextStatus == VulnerabilityStatus.Closed)
        {
            v.ClosedAt = DateTime.UtcNow;
        }

        db.VulnerabilityHistory.Add(new VulnerabilityHistoryEntity
        {
            VulnerabilityId = v.Id,
            ChangeType = nextStatus == VulnerabilityStatus.Closed ? VulnerabilityChangeType.Closed : VulnerabilityChangeType.StatusChanged,
            OldValue = old,
            NewValue = nextStatus.ToString(),
            Note = $"Status changed to {nextStatus}",
            ChangedByUserId = actorUserId,
            ChangedAt = DateTime.UtcNow
        });

        db.AuditLogs.Add(new AuditLogEntity
        {
            UserId = actorUserId,
            Action = "StatusChanged",
            TargetType = "Vulnerability",
            TargetId = v.Id.ToString(),
            Details = $"Changed {v.CveId} from {old} to {nextStatus}",
            IpAddress = ip,
            Timestamp = DateTime.UtcNow
        });

        await db.SaveChangesAsync();
        return (true, $"Status updated to {nextStatus}.");
    }

    public async Task RequestRescanAsync(int vulnId, string actorUserId, string ip = "127.0.0.1")
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var v = await db.Vulnerabilities.Include(x => x.Asset).FirstOrDefaultAsync(x => x.Id == vulnId);
        if (v is null) return;

        db.VulnerabilityHistory.Add(new VulnerabilityHistoryEntity
        {
            VulnerabilityId = v.Id,
            ChangeType = VulnerabilityChangeType.Comment,
            NewValue = "Rescan requested",
            Note = $"Queued targeted Greenbone verification rescan for {v.Asset.Hostname}.",
            ChangedByUserId = actorUserId,
            ChangedAt = DateTime.UtcNow
        });

        db.AuditLogs.Add(new AuditLogEntity
        {
            UserId = actorUserId,
            Action = "RescanRequested",
            TargetType = "Vulnerability",
            TargetId = v.Id.ToString(),
            Details = $"Requested rescan for {v.CveId} on {v.Asset.Hostname}",
            IpAddress = ip,
            Timestamp = DateTime.UtcNow
        });

        await db.SaveChangesAsync();
    }

    public async Task VerifyAndCloseAsync(int vulnId, string actorUserId, string ip = "127.0.0.1")
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var v = await db.Vulnerabilities.Include(x => x.Asset).FirstOrDefaultAsync(x => x.Id == vulnId);
        if (v is null) return;

        var latestBatch = await db.ImportBatches
            .Where(b => b.Status == ImportStatus.Completed || b.Status == ImportStatus.CompletedWithWarnings)
            .OrderByDescending(b => b.CompletedAt)
            .FirstOrDefaultAsync();

        if (latestBatch is null) return;

        var now = DateTime.UtcNow;
        var old = v.Status.ToString();
        v.VerifiedByImportBatchId = latestBatch.Id;
        v.Status = VulnerabilityStatus.Closed;
        v.ClosedAt = now;

        db.VulnerabilityHistory.Add(new VulnerabilityHistoryEntity
        {
            VulnerabilityId = v.Id,
            ChangeType = VulnerabilityChangeType.RescanVerified,
            OldValue = old,
            NewValue = "Verified",
            Note = $"Verified absent in Greenbone batch #{latestBatch.Id} ({latestBatch.FileName}).",
            ChangedByUserId = actorUserId,
            ImportBatchId = latestBatch.Id,
            ChangedAt = now
        });

        db.VulnerabilityHistory.Add(new VulnerabilityHistoryEntity
        {
            VulnerabilityId = v.Id,
            ChangeType = VulnerabilityChangeType.Closed,
            OldValue = old,
            NewValue = "Closed",
            Note = $"Closed with verified rescan batch #{latestBatch.Id}.",
            ChangedByUserId = actorUserId,
            ImportBatchId = latestBatch.Id,
            ChangedAt = now
        });

        db.AuditLogs.Add(new AuditLogEntity
        {
            UserId = actorUserId,
            Action = "FindingClosed",
            TargetType = "Vulnerability",
            TargetId = v.Id.ToString(),
            Details = $"Closed {v.CveId} on {v.Asset.Hostname} using rescan batch #{latestBatch.Id}",
            IpAddress = ip,
            Timestamp = now
        });

        await db.SaveChangesAsync();
    }

    public async Task NudgeOverdueAsync(int vulnId, string actorUserId, string ip = "127.0.0.1")
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var v = await db.Vulnerabilities.Include(x => x.Asset).Include(x => x.Owner).FirstOrDefaultAsync(x => x.Id == vulnId);
        if (v is null) return;

        db.Alerts.Add(new AlertEntity
        {
            Type = AlertEventType.SlaOverdue,
            Message = $"SLA reminder: {v.CveId} on {v.Asset.Hostname} is overdue.",
            VulnerabilityId = v.Id,
            RecipientUserId = v.OwnerUserId ?? actorUserId,
            CreatedAt = DateTime.UtcNow
        });

        db.AuditLogs.Add(new AuditLogEntity
        {
            UserId = actorUserId,
            Action = "NudgeSent",
            TargetType = "Vulnerability",
            TargetId = v.Id.ToString(),
            Details = $"Sent SLA reminder to {v.Owner?.FullName ?? "owner"} for {v.CveId}",
            IpAddress = ip,
            Timestamp = DateTime.UtcNow
        });

        await db.SaveChangesAsync();
    }
}
