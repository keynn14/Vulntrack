/* ============================================================================
   VulnTrack — Dashboard Views & Parameterized T-SQL Queries (SQL Server 2019+)
   Role scoping note: Pass @OwnerUserId = NULL for Admin/Analyst, or the
   signed-in user's Id for Asset Owner so owners only see their own findings.
   ============================================================================ */

/* 1. Summary KPIs (Total Open, Critical, Overdue, Closed This Month) */
CREATE OR ALTER VIEW dbo.vw_DashboardSummary AS
SELECT
    COUNT(CASE WHEN Status IN (1, 2, 3) THEN 1 END) AS TotalOpen,
    COUNT(CASE WHEN Status IN (1, 2, 3) AND Severity = 5 THEN 1 END) AS CriticalCount,
    COUNT(CASE WHEN Status NOT IN (4, 5) AND DueDate < SYSUTCDATETIME() THEN 1 END) AS OverdueCount,
    COUNT(CASE
        WHEN Status = 4
         AND ClosedAt >= DATEFROMPARTS(YEAR(SYSUTCDATETIME()), MONTH(SYSUTCDATETIME()), 1)
        THEN 1 END) AS ClosedThisMonth
FROM dbo.Vulnerabilities;
GO

/* 2. Findings by Severity (Active / Open scope) */
CREATE OR ALTER VIEW dbo.vw_FindingsBySeverity AS
SELECT
    Severity,
    CASE Severity
        WHEN 5 THEN N'Critical'
        WHEN 4 THEN N'High'
        WHEN 3 THEN N'Medium'
        WHEN 2 THEN N'Low'
        ELSE N'Info'
    END AS SeverityName,
    COUNT(*) AS FindingCount
FROM dbo.Vulnerabilities
WHERE Status IN (1, 2, 3)
GROUP BY Severity;
GO

/* 3. Findings by Status */
CREATE OR ALTER VIEW dbo.vw_FindingsByStatus AS
SELECT
    Status,
    CASE Status
        WHEN 1 THEN N'Open'
        WHEN 2 THEN N'InProgress'
        WHEN 3 THEN N'FixedAwaitingVerification'
        WHEN 4 THEN N'Closed'
        ELSE N'AcceptedRisk'
    END AS StatusName,
    COUNT(*) AS FindingCount
FROM dbo.Vulnerabilities
GROUP BY Status;
GO

/* 4. Open vs Closed per Week for the Last 12 Weeks */
CREATE OR ALTER VIEW dbo.vw_OpenVsClosedLast12Weeks AS
WITH Weeks AS (
    SELECT 0 AS WeekOffset
    UNION ALL
    SELECT WeekOffset + 1 FROM Weeks WHERE WeekOffset < 11
),
WeekRanges AS (
    SELECT
        DATEADD(WEEK, -WeekOffset, DATEADD(DAY, 1 - DATEPART(WEEKDAY, CAST(SYSUTCDATETIME() AS DATE)), CAST(SYSUTCDATETIME() AS DATE))) AS WeekStart,
        DATEADD(WEEK, 1 - WeekOffset, DATEADD(DAY, 1 - DATEPART(WEEKDAY, CAST(SYSUTCDATETIME() AS DATE)), CAST(SYSUTCDATETIME() AS DATE))) AS WeekEnd
    FROM Weeks
)
SELECT
    w.WeekStart,
    COUNT(DISTINCT CASE WHEN v.DetectedAt >= w.WeekStart AND v.DetectedAt < w.WeekEnd THEN v.Id END) AS OpenedCount,
    COUNT(DISTINCT CASE WHEN v.ClosedAt   >= w.WeekStart AND v.ClosedAt   < w.WeekEnd THEN v.Id END) AS ClosedCount
FROM WeekRanges w
LEFT JOIN dbo.Vulnerabilities v
    ON (v.DetectedAt >= w.WeekStart AND v.DetectedAt < w.WeekEnd)
    OR (v.ClosedAt   >= w.WeekStart AND v.ClosedAt   < w.WeekEnd)
GROUP BY w.WeekStart;
GO

/* 5. Top Critical Findings (sorted by CVSS DESC, then DaysOverdue DESC) */
CREATE OR ALTER VIEW dbo.vw_TopCriticalFindings AS
SELECT
    v.Id,
    v.CveId,
    v.Title,
    v.Severity,
    v.CvssScore,
    a.Hostname AS AssetHostname,
    u.FullName AS OwnerName,
    v.OwnerUserId,
    v.DueDate,
    CASE
        WHEN v.Status NOT IN (4, 5) AND v.DueDate < SYSUTCDATETIME()
            THEN DATEDIFF(DAY, v.DueDate, SYSUTCDATETIME())
        ELSE 0
    END AS DaysOverdue,
    v.Status
FROM dbo.Vulnerabilities v
INNER JOIN dbo.Assets a ON a.Id = v.AssetId
LEFT JOIN dbo.AspNetUsers u ON u.Id = v.OwnerUserId
WHERE v.Severity = 5
  AND v.Status IN (1, 2, 3);
GO

-- Usage example with ordering & optional Asset Owner filter:
-- SELECT TOP (10) * FROM dbo.vw_TopCriticalFindings
-- WHERE (@OwnerUserId IS NULL OR OwnerUserId = @OwnerUserId)
-- ORDER BY CvssScore DESC, DaysOverdue DESC;

/* 6. Verification Queue (Status = 3 / FixedAwaitingVerification) */
CREATE OR ALTER VIEW dbo.vw_VerificationQueue AS
SELECT
    v.Id,
    v.CveId,
    v.Title,
    v.Severity,
    v.CvssScore,
    a.Hostname AS AssetHostname,
    v.Port,
    v.Protocol,
    u.FullName AS OwnerName,
    v.FixedAt,
    v.LastSeenAt,
    b.FileName AS LastImportFile,
    b.CompletedAt AS LastRescanAt
FROM dbo.Vulnerabilities v
INNER JOIN dbo.Assets a ON a.Id = v.AssetId
LEFT JOIN dbo.AspNetUsers u ON u.Id = v.OwnerUserId
LEFT JOIN dbo.ImportBatches b ON b.Id = v.LastImportBatchId
WHERE v.Status = 3;
GO
