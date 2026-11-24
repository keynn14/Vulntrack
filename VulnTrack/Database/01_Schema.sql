/* ============================================================================
   VulnTrack — Database Schema (T-SQL for Microsoft SQL Server 2019+)
   EF Core Code-First + ASP.NET Core Identity
   All dates are UTC datetime2(0). Enums are stored as tinyint with CHECK.
   Foreign keys use ON DELETE NO ACTION; Users and Assets are soft-deleted.
   ============================================================================ */

SET NOCOUNT ON;
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

/* ----------------------------------------------------------------------------
   1. ASP.NET Core Identity Tables (AspNetUsers extended with domain columns)
   ---------------------------------------------------------------------------- */
CREATE TABLE dbo.AspNetRoles (
    Id                  NVARCHAR(450)   NOT NULL,
    Name                NVARCHAR(256)   NULL,
    NormalizedName      NVARCHAR(256)   NULL,
    ConcurrencyStamp    NVARCHAR(MAX)   NULL,
    CONSTRAINT PK_AspNetRoles PRIMARY KEY (Id)
);
GO

CREATE UNIQUE INDEX RoleNameIndex
    ON dbo.AspNetRoles (NormalizedName)
    WHERE NormalizedName IS NOT NULL;
GO

CREATE TABLE dbo.AspNetUsers (
    Id                      NVARCHAR(450)       NOT NULL,
    UserName                NVARCHAR(256)       NULL,
    NormalizedUserName      NVARCHAR(256)       NULL,
    Email                   NVARCHAR(256)       NULL,
    NormalizedEmail         NVARCHAR(256)       NULL,
    EmailConfirmed          BIT                 NOT NULL CONSTRAINT DF_AspNetUsers_EmailConfirmed DEFAULT (0),
    PasswordHash            NVARCHAR(MAX)       NULL,
    SecurityStamp           NVARCHAR(MAX)       NULL,
    ConcurrencyStamp        NVARCHAR(MAX)       NULL,
    PhoneNumber             NVARCHAR(MAX)       NULL,
    PhoneNumberConfirmed    BIT                 NOT NULL CONSTRAINT DF_AspNetUsers_PhoneConfirmed DEFAULT (0),
    TwoFactorEnabled        BIT                 NOT NULL CONSTRAINT DF_AspNetUsers_TwoFactor DEFAULT (0),
    LockoutEnd              DATETIMEOFFSET(7)   NULL,
    LockoutEnabled          BIT                 NOT NULL CONSTRAINT DF_AspNetUsers_Lockout DEFAULT (1),
    AccessFailedCount       INT                 NOT NULL CONSTRAINT DF_AspNetUsers_AccessFailed DEFAULT (0),
    -- VulnTrack extensions
    FullName                NVARCHAR(120)       NOT NULL,
    Department              NVARCHAR(100)       NOT NULL,
    IsActive                BIT                 NOT NULL CONSTRAINT DF_AspNetUsers_IsActive DEFAULT (1),
    LastLoginAt             DATETIME2(0)        NULL,
    CONSTRAINT PK_AspNetUsers PRIMARY KEY (Id)
);
GO

CREATE INDEX EmailIndex ON dbo.AspNetUsers (NormalizedEmail);
GO

CREATE UNIQUE INDEX UserNameIndex
    ON dbo.AspNetUsers (NormalizedUserName)
    WHERE NormalizedUserName IS NOT NULL;
GO

CREATE TABLE dbo.AspNetRoleClaims (
    Id          INT             IDENTITY(1,1) NOT NULL,
    RoleId      NVARCHAR(450)   NOT NULL,
    ClaimType   NVARCHAR(MAX)   NULL,
    ClaimValue  NVARCHAR(MAX)   NULL,
    CONSTRAINT PK_AspNetRoleClaims PRIMARY KEY (Id),
    CONSTRAINT FK_AspNetRoleClaims_AspNetRoles FOREIGN KEY (RoleId)
        REFERENCES dbo.AspNetRoles (Id) ON DELETE CASCADE
);
GO

CREATE INDEX IX_AspNetRoleClaims_RoleId ON dbo.AspNetRoleClaims (RoleId);
GO

CREATE TABLE dbo.AspNetUserClaims (
    Id          INT             IDENTITY(1,1) NOT NULL,
    UserId      NVARCHAR(450)   NOT NULL,
    ClaimType   NVARCHAR(MAX)   NULL,
    ClaimValue  NVARCHAR(MAX)   NULL,
    CONSTRAINT PK_AspNetUserClaims PRIMARY KEY (Id),
    CONSTRAINT FK_AspNetUserClaims_AspNetUsers FOREIGN KEY (UserId)
        REFERENCES dbo.AspNetUsers (Id) ON DELETE CASCADE
);
GO

CREATE INDEX IX_AspNetUserClaims_UserId ON dbo.AspNetUserClaims (UserId);
GO

CREATE TABLE dbo.AspNetUserLogins (
    LoginProvider       NVARCHAR(450)   NOT NULL,
    ProviderKey         NVARCHAR(450)   NOT NULL,
    ProviderDisplayName NVARCHAR(MAX)   NULL,
    UserId              NVARCHAR(450)   NOT NULL,
    CONSTRAINT PK_AspNetUserLogins PRIMARY KEY (LoginProvider, ProviderKey),
    CONSTRAINT FK_AspNetUserLogins_AspNetUsers FOREIGN KEY (UserId)
        REFERENCES dbo.AspNetUsers (Id) ON DELETE CASCADE
);
GO

CREATE INDEX IX_AspNetUserLogins_UserId ON dbo.AspNetUserLogins (UserId);
GO

CREATE TABLE dbo.AspNetUserRoles (
    UserId      NVARCHAR(450)   NOT NULL,
    RoleId      NVARCHAR(450)   NOT NULL,
    CONSTRAINT PK_AspNetUserRoles PRIMARY KEY (UserId, RoleId),
    CONSTRAINT FK_AspNetUserRoles_AspNetRoles FOREIGN KEY (RoleId)
        REFERENCES dbo.AspNetRoles (Id) ON DELETE CASCADE,
    CONSTRAINT FK_AspNetUserRoles_AspNetUsers FOREIGN KEY (UserId)
        REFERENCES dbo.AspNetUsers (Id) ON DELETE CASCADE
);
GO

CREATE INDEX IX_AspNetUserRoles_RoleId ON dbo.AspNetUserRoles (RoleId);
GO

CREATE TABLE dbo.AspNetUserTokens (
    UserId          NVARCHAR(450)   NOT NULL,
    LoginProvider   NVARCHAR(450)   NOT NULL,
    Name            NVARCHAR(450)   NOT NULL,
    Value           NVARCHAR(MAX)   NULL,
    CONSTRAINT PK_AspNetUserTokens PRIMARY KEY (UserId, LoginProvider, Name),
    CONSTRAINT FK_AspNetUserTokens_AspNetUsers FOREIGN KEY (UserId)
        REFERENCES dbo.AspNetUsers (Id) ON DELETE CASCADE
);
GO

/* ----------------------------------------------------------------------------
   2. Assets
      Criticality: 1=Low, 2=Medium, 3=High
   ---------------------------------------------------------------------------- */
CREATE TABLE dbo.Assets (
    Id                  INT             IDENTITY(1,1) NOT NULL,
    Hostname            NVARCHAR(128)   NOT NULL,
    IpAddress           NVARCHAR(45)    NOT NULL,
    OperatingSystem     NVARCHAR(128)   NOT NULL,
    Department          NVARCHAR(100)   NOT NULL,
    Criticality         TINYINT         NOT NULL,
    OwnerUserId         NVARCHAR(450)   NOT NULL,
    BusinessImpactNotes NVARCHAR(1000)  NULL,
    IsActive            BIT             NOT NULL CONSTRAINT DF_Assets_IsActive DEFAULT (1),
    CreatedAt           DATETIME2(0)    NOT NULL CONSTRAINT DF_Assets_CreatedAt DEFAULT (SYSUTCDATETIME()),
    LastScannedAt       DATETIME2(0)    NULL,
    CONSTRAINT PK_Assets PRIMARY KEY (Id),
    CONSTRAINT UQ_Assets_Hostname_IpAddress UNIQUE (Hostname, IpAddress),
    CONSTRAINT CK_Assets_Criticality CHECK (Criticality BETWEEN 1 AND 3),
    CONSTRAINT FK_Assets_AspNetUsers FOREIGN KEY (OwnerUserId)
        REFERENCES dbo.AspNetUsers (Id) ON DELETE NO ACTION
);
GO

CREATE INDEX IX_Assets_OwnerUserId ON dbo.Assets (OwnerUserId);
GO

/* ----------------------------------------------------------------------------
   3. ImportBatches
      Source: 1=GreenboneApi, 2=ManualUpload
      Status: 1=Running, 2=Completed, 3=CompletedWithWarnings, 4=Failed, 5=RolledBack
   ---------------------------------------------------------------------------- */
CREATE TABLE dbo.ImportBatches (
    Id                          INT             IDENTITY(1,1) NOT NULL,
    Source                      TINYINT         NOT NULL,
    FileName                    NVARCHAR(260)   NOT NULL,
    TargetName                  NVARCHAR(160)   NOT NULL,
    StartedAt                   DATETIME2(0)    NOT NULL CONSTRAINT DF_ImportBatches_StartedAt DEFAULT (SYSUTCDATETIME()),
    CompletedAt                 DATETIME2(0)    NULL,
    Status                      TINYINT         NOT NULL CONSTRAINT DF_ImportBatches_Status DEFAULT (1),
    TotalFindings               INT             NOT NULL CONSTRAINT DF_ImportBatches_Total DEFAULT (0),
    NewCount                    INT             NOT NULL CONSTRAINT DF_ImportBatches_New DEFAULT (0),
    UpdatedCount                INT             NOT NULL CONSTRAINT DF_ImportBatches_Updated DEFAULT (0),
    MarkedForVerificationCount  INT             NOT NULL CONSTRAINT DF_ImportBatches_Marked DEFAULT (0),
    ReopenedCount               INT             NOT NULL CONSTRAINT DF_ImportBatches_Reopened DEFAULT (0),
    ErrorMessage                NVARCHAR(2000)  NULL,
    ImportedByUserId            NVARCHAR(450)   NOT NULL,
    CONSTRAINT PK_ImportBatches PRIMARY KEY (Id),
    CONSTRAINT CK_ImportBatches_Source CHECK (Source IN (1, 2)),
    CONSTRAINT CK_ImportBatches_Status CHECK (Status BETWEEN 1 AND 5),
    CONSTRAINT FK_ImportBatches_AspNetUsers FOREIGN KEY (ImportedByUserId)
        REFERENCES dbo.AspNetUsers (Id) ON DELETE NO ACTION
);
GO

CREATE INDEX IX_ImportBatches_StartedAt ON dbo.ImportBatches (StartedAt DESC);
GO

/* ----------------------------------------------------------------------------
   4. Vulnerabilities
      Severity: 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical
      Status:   1=Open, 2=InProgress, 3=FixedAwaitingVerification, 4=Closed, 5=AcceptedRisk
      Rule:     Closed (4) requires VerifiedByImportBatchId IS NOT NULL and ClosedAt IS NOT NULL.
   ---------------------------------------------------------------------------- */
CREATE TABLE dbo.Vulnerabilities (
    Id                      INT             IDENTITY(1,1) NOT NULL,
    CveId                   NVARCHAR(32)    NOT NULL,
    Title                   NVARCHAR(250)   NOT NULL,
    Description             NVARCHAR(MAX)   NULL,
    Severity                TINYINT         NOT NULL,
    CvssScore               DECIMAL(3,1)    NOT NULL CONSTRAINT DF_Vulnerabilities_CvssScore DEFAULT (0.0),
    AssetId                 INT             NOT NULL,
    Port                    INT             NOT NULL CONSTRAINT DF_Vulnerabilities_Port DEFAULT (0),
    Protocol                NVARCHAR(16)    NOT NULL CONSTRAINT DF_Vulnerabilities_Protocol DEFAULT (N'tcp'),
    Service                 NVARCHAR(100)   NULL,
    BusinessImpact          NVARCHAR(500)   NULL,
    RecommendedFix          NVARCHAR(MAX)   NULL,
    OwnerUserId             NVARCHAR(450)   NULL,
    DueDate                 DATETIME2(0)    NOT NULL,
    Status                  TINYINT         NOT NULL CONSTRAINT DF_Vulnerabilities_Status DEFAULT (1),
    DetectedAt              DATETIME2(0)    NOT NULL CONSTRAINT DF_Vulnerabilities_DetectedAt DEFAULT (SYSUTCDATETIME()),
    LastSeenAt              DATETIME2(0)    NOT NULL CONSTRAINT DF_Vulnerabilities_LastSeenAt DEFAULT (SYSUTCDATETIME()),
    FixedAt                 DATETIME2(0)    NULL,
    ClosedAt                DATETIME2(0)    NULL,
    CreatedByImportBatchId  INT             NULL,
    LastImportBatchId       INT             NULL,
    VerifiedByImportBatchId INT             NULL,
    RowVersion              ROWVERSION      NOT NULL,
    CONSTRAINT PK_Vulnerabilities PRIMARY KEY (Id),
    CONSTRAINT UQ_Vulnerabilities_CveId_AssetId_Port UNIQUE (CveId, AssetId, Port),
    CONSTRAINT CK_Vulnerabilities_Severity CHECK (Severity BETWEEN 1 AND 5),
    CONSTRAINT CK_Vulnerabilities_CvssScore CHECK (CvssScore >= 0.0 AND CvssScore <= 10.0),
    CONSTRAINT CK_Vulnerabilities_Port CHECK (Port >= 0 AND Port <= 65535),
    CONSTRAINT CK_Vulnerabilities_Status CHECK (Status BETWEEN 1 AND 5),
    CONSTRAINT CK_Vulnerabilities_ClosedRequiresRescan CHECK (
        Status <> 4 OR (VerifiedByImportBatchId IS NOT NULL AND ClosedAt IS NOT NULL)
    ),
    CONSTRAINT FK_Vulnerabilities_Assets FOREIGN KEY (AssetId)
        REFERENCES dbo.Assets (Id) ON DELETE NO ACTION,
    CONSTRAINT FK_Vulnerabilities_AspNetUsers FOREIGN KEY (OwnerUserId)
        REFERENCES dbo.AspNetUsers (Id) ON DELETE NO ACTION,
    CONSTRAINT FK_Vulnerabilities_ImportBatches_CreatedBy FOREIGN KEY (CreatedByImportBatchId)
        REFERENCES dbo.ImportBatches (Id) ON DELETE NO ACTION,
    CONSTRAINT FK_Vulnerabilities_ImportBatches_LastSeen FOREIGN KEY (LastImportBatchId)
        REFERENCES dbo.ImportBatches (Id) ON DELETE NO ACTION,
    CONSTRAINT FK_Vulnerabilities_ImportBatches_VerifiedBy FOREIGN KEY (VerifiedByImportBatchId)
        REFERENCES dbo.ImportBatches (Id) ON DELETE NO ACTION
);
GO

CREATE INDEX IX_Vulnerabilities_Status_Severity
    ON dbo.Vulnerabilities (Status, Severity)
    INCLUDE (CvssScore, DueDate, AssetId, OwnerUserId);
GO

CREATE INDEX IX_Vulnerabilities_OwnerUserId_Status
    ON dbo.Vulnerabilities (OwnerUserId, Status)
    INCLUDE (Severity, DueDate, AssetId);
GO

CREATE INDEX IX_Vulnerabilities_DueDate
    ON dbo.Vulnerabilities (DueDate)
    INCLUDE (Status, Severity, OwnerUserId);
GO

CREATE INDEX IX_Vulnerabilities_AssetId
    ON dbo.Vulnerabilities (AssetId);
GO

/* ----------------------------------------------------------------------------
   5. VulnerabilityHistory
      ChangeType: 1=Imported, 2=Ranked, 3=OwnerAssigned, 4=DueDateChanged,
                  5=StatusChanged, 6=Reopened, 7=RescanVerified, 8=Closed, 9=Comment
   ---------------------------------------------------------------------------- */
CREATE TABLE dbo.VulnerabilityHistory (
    Id              INT             IDENTITY(1,1) NOT NULL,
    VulnerabilityId INT             NOT NULL,
    ChangeType      TINYINT         NOT NULL,
    OldValue        NVARCHAR(500)   NULL,
    NewValue        NVARCHAR(500)   NULL,
    Note            NVARCHAR(1000)  NULL,
    ChangedByUserId NVARCHAR(450)   NULL,
    ImportBatchId   INT             NULL,
    ChangedAt       DATETIME2(0)    NOT NULL CONSTRAINT DF_VulnerabilityHistory_ChangedAt DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT PK_VulnerabilityHistory PRIMARY KEY (Id),
    CONSTRAINT CK_VulnerabilityHistory_ChangeType CHECK (ChangeType BETWEEN 1 AND 9),
    CONSTRAINT FK_VulnerabilityHistory_Vulnerabilities FOREIGN KEY (VulnerabilityId)
        REFERENCES dbo.Vulnerabilities (Id) ON DELETE NO ACTION,
    CONSTRAINT FK_VulnerabilityHistory_AspNetUsers FOREIGN KEY (ChangedByUserId)
        REFERENCES dbo.AspNetUsers (Id) ON DELETE NO ACTION,
    CONSTRAINT FK_VulnerabilityHistory_ImportBatches FOREIGN KEY (ImportBatchId)
        REFERENCES dbo.ImportBatches (Id) ON DELETE NO ACTION
);
GO

CREATE INDEX IX_VulnerabilityHistory_VulnerabilityId_ChangedAt
    ON dbo.VulnerabilityHistory (VulnerabilityId, ChangedAt DESC);
GO

CREATE INDEX IX_VulnerabilityHistory_ImportBatchId
    ON dbo.VulnerabilityHistory (ImportBatchId)
    WHERE ImportBatchId IS NOT NULL;
GO

/* ----------------------------------------------------------------------------
   6. SlaRules
      Severity: 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical
   ---------------------------------------------------------------------------- */
CREATE TABLE dbo.SlaRules (
    Id          INT         IDENTITY(1,1) NOT NULL,
    Severity    TINYINT     NOT NULL,
    DueDays     INT         NOT NULL,
    CONSTRAINT PK_SlaRules PRIMARY KEY (Id),
    CONSTRAINT UQ_SlaRules_Severity UNIQUE (Severity),
    CONSTRAINT CK_SlaRules_Severity CHECK (Severity BETWEEN 1 AND 5),
    CONSTRAINT CK_SlaRules_DueDays CHECK (DueDays > 0)
);
GO

/* ----------------------------------------------------------------------------
   7. Alerts
      Type: 1=CriticalFinding, 2=SlaOverdue, 3=RescanResult, 4=ImportFailed
   ---------------------------------------------------------------------------- */
CREATE TABLE dbo.Alerts (
    Id              INT             IDENTITY(1,1) NOT NULL,
    [Type]          TINYINT         NOT NULL,
    Message         NVARCHAR(500)   NOT NULL,
    VulnerabilityId INT             NULL,
    RecipientUserId NVARCHAR(450)   NOT NULL,
    IsRead          BIT             NOT NULL CONSTRAINT DF_Alerts_IsRead DEFAULT (0),
    CreatedAt       DATETIME2(0)    NOT NULL CONSTRAINT DF_Alerts_CreatedAt DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT PK_Alerts PRIMARY KEY (Id),
    CONSTRAINT CK_Alerts_Type CHECK ([Type] BETWEEN 1 AND 4),
    CONSTRAINT FK_Alerts_Vulnerabilities FOREIGN KEY (VulnerabilityId)
        REFERENCES dbo.Vulnerabilities (Id) ON DELETE NO ACTION,
    CONSTRAINT FK_Alerts_AspNetUsers FOREIGN KEY (RecipientUserId)
        REFERENCES dbo.AspNetUsers (Id) ON DELETE NO ACTION
);
GO

CREATE INDEX IX_Alerts_RecipientUserId_IsRead
    ON dbo.Alerts (RecipientUserId, IsRead)
    INCLUDE (CreatedAt, [Type]);
GO

/* ----------------------------------------------------------------------------
   8. AuditLogs (Append-Only)
   ---------------------------------------------------------------------------- */
CREATE TABLE dbo.AuditLogs (
    Id          INT             IDENTITY(1,1) NOT NULL,
    UserId      NVARCHAR(450)   NULL,
    Action      NVARCHAR(100)   NOT NULL,
    TargetType  NVARCHAR(60)    NOT NULL,
    TargetId    NVARCHAR(64)    NOT NULL,
    Details     NVARCHAR(1000)  NULL,
    IpAddress   NVARCHAR(45)    NOT NULL,
    [Timestamp] DATETIME2(0)    NOT NULL CONSTRAINT DF_AuditLogs_Timestamp DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT PK_AuditLogs PRIMARY KEY (Id),
    CONSTRAINT FK_AuditLogs_AspNetUsers FOREIGN KEY (UserId)
        REFERENCES dbo.AspNetUsers (Id) ON DELETE NO ACTION
);
GO

CREATE INDEX IX_AuditLogs_Timestamp
    ON dbo.AuditLogs ([Timestamp] DESC)
    INCLUDE (UserId, Action, TargetType, TargetId);
GO

/* ----------------------------------------------------------------------------
   9. ReportRecords
      Format: 1=PDF, 2=CSV
   ---------------------------------------------------------------------------- */
CREATE TABLE dbo.ReportRecords (
    Id              INT             IDENTITY(1,1) NOT NULL,
    Name            NVARCHAR(200)   NOT NULL,
    [Type]          NVARCHAR(60)    NOT NULL,
    Format          TINYINT         NOT NULL,
    FiltersJson     NVARCHAR(MAX)   NULL,
    CreatedByUserId NVARCHAR(450)   NOT NULL,
    CreatedAt       DATETIME2(0)    NOT NULL CONSTRAINT DF_ReportRecords_CreatedAt DEFAULT (SYSUTCDATETIME()),
    FilePath        NVARCHAR(400)   NULL,
    CONSTRAINT PK_ReportRecords PRIMARY KEY (Id),
    CONSTRAINT CK_ReportRecords_Format CHECK (Format IN (1, 2)),
    CONSTRAINT FK_ReportRecords_AspNetUsers FOREIGN KEY (CreatedByUserId)
        REFERENCES dbo.AspNetUsers (Id) ON DELETE NO ACTION
);
GO

/* ----------------------------------------------------------------------------
   10. AppSettings (Key/Value; secrets stored encrypted or as vault references)
   ---------------------------------------------------------------------------- */
CREATE TABLE dbo.AppSettings (
    [Key]           NVARCHAR(100)   NOT NULL,
    [Value]         NVARCHAR(2000)  NOT NULL,
    IsEncrypted     BIT             NOT NULL CONSTRAINT DF_AppSettings_IsEncrypted DEFAULT (0),
    Description     NVARCHAR(250)   NULL,
    UpdatedByUserId NVARCHAR(450)   NULL,
    UpdatedAt       DATETIME2(0)    NOT NULL CONSTRAINT DF_AppSettings_UpdatedAt DEFAULT (SYSUTCDATETIME()),
    CONSTRAINT PK_AppSettings PRIMARY KEY ([Key]),
    CONSTRAINT FK_AppSettings_AspNetUsers FOREIGN KEY (UpdatedByUserId)
        REFERENCES dbo.AspNetUsers (Id) ON DELETE NO ACTION
);
GO
