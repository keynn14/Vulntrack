using System.Text;
using System.Threading.Channels;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using VulnTrack.Data;
using VulnTrack.Data.Entities;

namespace VulnTrack.Services.Greenbone;

public sealed record ScanJobRequest(
    string TargetName,
    IReadOnlyList<string> Hosts,
    string RequestedByUserId,
    ImportOptions Options
);

public sealed class GreenboneScanQueue
{
    private readonly Channel<ScanJobRequest> _channel = Channel.CreateUnbounded<ScanJobRequest>();

    public ValueTask EnqueueAsync(ScanJobRequest request, CancellationToken ct = default) =>
        _channel.Writer.WriteAsync(request, ct);

    public IAsyncEnumerable<ScanJobRequest> ReadAllAsync(CancellationToken ct) =>
        _channel.Reader.ReadAllAsync(ct);
}

public sealed class GreenboneScanBackgroundService : BackgroundService
{
    private readonly GreenboneScanQueue _queue;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IDbContextFactory<AppDbContext> _dbFactory;
    private readonly GreenboneBridgeOptions _options;
    private readonly ILogger<GreenboneScanBackgroundService> _logger;

    public GreenboneScanBackgroundService(
        GreenboneScanQueue queue,
        IServiceScopeFactory scopeFactory,
        IDbContextFactory<AppDbContext> dbFactory,
        IOptions<GreenboneBridgeOptions> options,
        ILogger<GreenboneScanBackgroundService> logger)
    {
        _queue = queue;
        _scopeFactory = scopeFactory;
        _dbFactory = dbFactory;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var job in _queue.ReadAllAsync(stoppingToken))
        {
            try
            {
                await RunJobAsync(job, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Live Greenbone scan job failed for target {Target}", job.TargetName);
            }
        }
    }

    private async Task RunJobAsync(ScanJobRequest job, CancellationToken ct)
    {
        // Security rule: reject scan requests for hosts not registered as active authorized assets.
        await using (var db = await _dbFactory.CreateDbContextAsync(ct))
        {
            var authorized = await db.Assets
                .Where(a => a.IsActive)
                .Select(a => new { a.Hostname, a.IpAddress })
                .ToListAsync(ct);

            var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var a in authorized)
            {
                allowed.Add(a.Hostname);
                allowed.Add(a.IpAddress);
            }

            var unauthorized = job.Hosts.Where(h => !allowed.Contains(h)).ToList();
            if (unauthorized.Count > 0)
            {
                var msg = $"Rejected unauthorized scan targets: {string.Join(", ", unauthorized)}";
                _logger.LogWarning(msg);
                db.AuditLogs.Add(new AuditLogEntity
                {
                    UserId = job.RequestedByUserId,
                    Action = "UnauthorizedScanRejected",
                    TargetType = "ScanJob",
                    TargetId = job.TargetName,
                    Details = msg,
                    IpAddress = job.Options.IpAddress,
                    Timestamp = DateTime.UtcNow
                });
                await db.SaveChangesAsync(ct);
                return;
            }
        }

        using var scope = _scopeFactory.CreateScope();
        var client = scope.ServiceProvider.GetRequiredService<GreenboneBridgeClient>();
        var importService = scope.ServiceProvider.GetRequiredService<IImportService>();

        _logger.LogInformation("Starting live Greenbone scan '{Target}' for {Count} authorized host(s).", job.TargetName, job.Hosts.Count);
        var started = await client.StartScanAsync(job.TargetName, job.Hosts, ct);

        while (!ct.IsCancellationRequested)
        {
            var status = await client.GetStatusAsync(started.TaskId, ct);
            _logger.LogInformation("Greenbone task {TaskId}: {Status} ({Progress}%)", started.TaskId, status.Status, status.Progress);

            if (string.Equals(status.Status, "Done", StringComparison.OrdinalIgnoreCase))
                break;

            if (status.Status.Contains("Stopped", StringComparison.OrdinalIgnoreCase) ||
                status.Status.Contains("Interrupted", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException($"Greenbone task {started.TaskId} ended with status '{status.Status}'.");
            }

            await Task.Delay(TimeSpan.FromSeconds(Math.Max(2, _options.PollIntervalSeconds)), ct);
        }

        var xml = await client.GetReportXmlAsync(started.ReportId, ct);
        using var ms = new MemoryStream(Encoding.UTF8.GetBytes(xml));

        var apiOptions = job.Options with { Source = ImportSource.GreenboneApi };
        await importService.ImportAsync(
            ms,
            $"gmp-{started.ReportId}.xml",
            job.TargetName,
            apiOptions,
            job.RequestedByUserId,
            progress: null,
            ct);
    }
}
