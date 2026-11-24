using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using VulnTrack.Data;
using VulnTrack.Data.Entities;
using VulnTrack.Services.Greenbone;
using Xunit;

namespace VulnTrack.Tests;

public sealed class GreenboneImportTests : IDisposable
{
    private readonly SqliteConnection _conn;
    private readonly TestDbFactory _factory;
    private readonly ImportService _service;
    private const string UserId = "test-analyst-1";

    public GreenboneImportTests()
    {
        _conn = new SqliteConnection("Data Source=:memory:");
        _conn.Open();

        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_conn)
            .Options;

        _factory = new TestDbFactory(options);

        using var db = _factory.CreateDbContext();
        db.Database.EnsureCreated();

        db.Users.Add(new ApplicationUser
        {
            Id = UserId,
            UserName = "analyst@vulntrack.local",
            Email = "analyst@vulntrack.local",
            FullName = "Test Analyst",
            Department = "SOC",
            IsActive = true
        });
        db.SlaRules.AddRange(
            new SlaRuleEntity { Severity = VulnerabilitySeverity.Critical, DueDays = 7 },
            new SlaRuleEntity { Severity = VulnerabilitySeverity.High, DueDays = 14 },
            new SlaRuleEntity { Severity = VulnerabilitySeverity.Medium, DueDays = 30 },
            new SlaRuleEntity { Severity = VulnerabilitySeverity.Low, DueDays = 90 },
            new SlaRuleEntity { Severity = VulnerabilitySeverity.Info, DueDays = 180 }
        );
        db.SaveChanges();

        _service = new ImportService(_factory, new GreenboneXmlParser(), NullLogger<ImportService>.Instance);
    }

    public void Dispose() => _conn.Dispose();

    private static MemoryStream XmlStream(string xml) => new(Encoding.UTF8.GetBytes(xml));

    private const string InitialScanXml = """
        <report>
          <results>
            <result>
              <name>Ivanti Connect Secure command injection</name>
              <host>10.20.0.4<hostname>vpn-gw-01</hostname></host>
              <port>443/tcp</port>
              <severity>9.1</severity>
              <threat>High</threat>
              <nvt oid="1.3.6.1.4.1.25623.1.0.109001">
                <refs><ref type="cve" id="CVE-2024-21887"/></refs>
                <solution>Apply Ivanti security update.</solution>
              </nvt>
              <description>Command injection vulnerability.</description>
            </result>
            <result>
              <name>OpenSSH Terrapin prefix truncation</name>
              <host>10.20.0.4<hostname>vpn-gw-01</hostname></host>
              <port>22/tcp</port>
              <severity>5.9</severity>
              <threat>Medium</threat>
              <nvt oid="1.3.6.1.4.1.25623.1.0.109002">
                <refs><ref type="cve" id="CVE-2023-48795"/></refs>
                <solution>Upgrade OpenSSH to 9.6+.</solution>
              </nvt>
              <description>Terrapin MITM attack.</description>
            </result>
          </results>
        </report>
        """;

    private const string SecondScanMissingTerrapinXml = """
        <report>
          <results>
            <result>
              <name>Ivanti Connect Secure command injection</name>
              <host>10.20.0.4<hostname>vpn-gw-01</hostname></host>
              <port>443/tcp</port>
              <severity>9.1</severity>
              <threat>High</threat>
              <nvt oid="1.3.6.1.4.1.25623.1.0.109001">
                <refs><ref type="cve" id="CVE-2024-21887"/></refs>
                <solution>Apply Ivanti security update.</solution>
              </nvt>
              <description>Still present.</description>
            </result>
          </results>
        </report>
        """;

    [Fact]
    public async Task NewFinding_IsImportedAsOpen_WithSlaAndCriticalAlert()
    {
        var summary = await _service.ImportAsync(XmlStream(InitialScanXml), "scan1.xml", "vpn", new ImportOptions(), UserId);

        Assert.Equal(2, summary.NewCount);
        Assert.Equal(0, summary.UpdatedCount);
        Assert.Equal(0, summary.ClosedCount);

        await using var db = await _factory.CreateDbContextAsync();
        var crit = await db.Vulnerabilities.SingleAsync(v => v.CveId == "CVE-2024-21887");
        Assert.Equal(VulnerabilityStatus.Open, crit.Status);
        Assert.Equal(VulnerabilitySeverity.Critical, crit.Severity);
        Assert.Equal(DateTime.UtcNow.Date.AddDays(7), crit.DueDate.Date);
        Assert.True(await db.Alerts.AnyAsync(a => a.Type == AlertEventType.CriticalFinding && a.VulnerabilityId == crit.Id));
        Assert.True(await db.VulnerabilityHistory.AnyAsync(h => h.VulnerabilityId == crit.Id && h.ChangeType == VulnerabilityChangeType.Imported));
    }

    [Fact]
    public async Task DuplicateFinding_MergesOnCveAssetPort()
    {
        await _service.ImportAsync(XmlStream(InitialScanXml), "scan1.xml", "vpn", new ImportOptions(), UserId);
        var second = await _service.ImportAsync(XmlStream(InitialScanXml), "scan2.xml", "vpn", new ImportOptions(), UserId);

        Assert.Equal(0, second.NewCount);
        Assert.Equal(2, second.UpdatedCount);

        await using var db = await _factory.CreateDbContextAsync();
        Assert.Equal(2, await db.Vulnerabilities.CountAsync());
    }

    [Fact]
    public async Task MissingOpenFinding_MovesToFixedAwaitingVerification_NeverStraightToClosed()
    {
        await _service.ImportAsync(XmlStream(InitialScanXml), "scan1.xml", "vpn", new ImportOptions(), UserId);
        var res = await _service.ImportAsync(XmlStream(SecondScanMissingTerrapinXml), "scan2.xml", "vpn", new ImportOptions(), UserId);

        Assert.Equal(1, res.MarkedForVerificationCount);
        Assert.Equal(0, res.ClosedCount);

        await using var db = await _factory.CreateDbContextAsync();
        var terrapin = await db.Vulnerabilities.SingleAsync(v => v.CveId == "CVE-2023-48795");
        Assert.Equal(VulnerabilityStatus.FixedAwaitingVerification, terrapin.Status);
        Assert.Null(terrapin.ClosedAt);
        Assert.Null(terrapin.VerifiedByImportBatchId);
    }

    [Fact]
    public async Task SecondRescanWithoutFinding_ClosesFixedAwaitingVerification()
    {
        await _service.ImportAsync(XmlStream(InitialScanXml), "scan1.xml", "vpn", new ImportOptions(), UserId);
        await _service.ImportAsync(XmlStream(SecondScanMissingTerrapinXml), "scan2.xml", "vpn", new ImportOptions(), UserId);
        var third = await _service.ImportAsync(XmlStream(SecondScanMissingTerrapinXml), "scan3.xml", "vpn", new ImportOptions(), UserId);

        Assert.Equal(1, third.ClosedCount);

        await using var db = await _factory.CreateDbContextAsync();
        var terrapin = await db.Vulnerabilities.SingleAsync(v => v.CveId == "CVE-2023-48795");
        Assert.Equal(VulnerabilityStatus.Closed, terrapin.Status);
        Assert.NotNull(terrapin.ClosedAt);
        Assert.Equal(third.BatchId, terrapin.VerifiedByImportBatchId);
        Assert.True(await db.VulnerabilityHistory.AnyAsync(h => h.VulnerabilityId == terrapin.Id && h.ChangeType == VulnerabilityChangeType.RescanVerified));
        Assert.True(await db.VulnerabilityHistory.AnyAsync(h => h.VulnerabilityId == terrapin.Id && h.ChangeType == VulnerabilityChangeType.Closed));
    }

    [Fact]
    public async Task ReappearingFinding_IsReopened_WithHistoryAndAlert()
    {
        await _service.ImportAsync(XmlStream(InitialScanXml), "scan1.xml", "vpn", new ImportOptions(), UserId);
        await _service.ImportAsync(XmlStream(SecondScanMissingTerrapinXml), "scan2.xml", "vpn", new ImportOptions(), UserId);
        var reappeared = await _service.ImportAsync(XmlStream(InitialScanXml), "scan3.xml", "vpn", new ImportOptions(), UserId);

        Assert.Equal(1, reappeared.ReopenedCount);

        await using var db = await _factory.CreateDbContextAsync();
        var terrapin = await db.Vulnerabilities.SingleAsync(v => v.CveId == "CVE-2023-48795");
        Assert.Equal(VulnerabilityStatus.InProgress, terrapin.Status);
        Assert.True(await db.VulnerabilityHistory.AnyAsync(h => h.VulnerabilityId == terrapin.Id && h.ChangeType == VulnerabilityChangeType.Reopened));
        Assert.True(await db.Alerts.AnyAsync(a => a.Type == AlertEventType.RescanResult && a.VulnerabilityId == terrapin.Id));
    }

    [Fact]
    public async Task AcceptedRisk_IsNeverChangedAutomatically()
    {
        await _service.ImportAsync(XmlStream(InitialScanXml), "scan1.xml", "vpn", new ImportOptions(), UserId);
        await using (var db = await _factory.CreateDbContextAsync())
        {
            var terrapin = await db.Vulnerabilities.SingleAsync(v => v.CveId == "CVE-2023-48795");
            terrapin.Status = VulnerabilityStatus.AcceptedRisk;
            await db.SaveChangesAsync();
        }

        var res = await _service.ImportAsync(XmlStream(SecondScanMissingTerrapinXml), "scan2.xml", "vpn", new ImportOptions(), UserId);
        Assert.Equal(0, res.MarkedForVerificationCount);
        Assert.Equal(0, res.ClosedCount);

        await using (var db = await _factory.CreateDbContextAsync())
        {
            var terrapin = await db.Vulnerabilities.SingleAsync(v => v.CveId == "CVE-2023-48795");
            Assert.Equal(VulnerabilityStatus.AcceptedRisk, terrapin.Status);
        }
    }

    [Fact]
    public async Task MalformedXml_FailsCleanly_AndRecordsFailedBatch()
    {
        const string brokenXml = "<report><results><result><name>Broken";

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            _service.ImportAsync(XmlStream(brokenXml), "broken.xml", "vpn", new ImportOptions(), UserId));

        await using var db = await _factory.CreateDbContextAsync();
        var failed = await db.ImportBatches.SingleAsync(b => b.FileName == "broken.xml");
        Assert.Equal(ImportStatus.Failed, failed.Status);
        Assert.False(string.IsNullOrWhiteSpace(failed.ErrorMessage));
    }

    private sealed class TestDbFactory : IDbContextFactory<AppDbContext>
    {
        private readonly DbContextOptions<AppDbContext> _options;
        public TestDbFactory(DbContextOptions<AppDbContext> options) => _options = options;
        public AppDbContext CreateDbContext() => new(_options);
        public Task<AppDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) => Task.FromResult(new AppDbContext(_options));
    }
}
