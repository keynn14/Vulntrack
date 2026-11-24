namespace VulnTrack.Models;

public class ImportRecord
{
    public string Id { get; set; } = "";
    public string FileName { get; set; } = "";
    public string Source { get; set; } = "Greenbone GMP";
    public string ScanTask { get; set; } = "";
    public DateTime ImportedAt { get; set; }
    public string ImportedBy { get; set; } = "";
    public int NewFindings { get; set; }
    public int UpdatedFindings { get; set; }
    public int MarkedFixed { get; set; }
    public string Status { get; set; } = "Completed";
    public string Notes { get; set; } = "";

    public int TotalFindings => NewFindings + UpdatedFindings + MarkedFixed;
}
