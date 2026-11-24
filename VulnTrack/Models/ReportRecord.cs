namespace VulnTrack.Models;

public class ReportRecord
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string ReportType { get; set; } = "";
    public string CreatedBy { get; set; } = "";
    public DateTime CreatedAt { get; set; }
    public string Format { get; set; } = "PDF";
    public string ScopeSummary { get; set; } = "";
}
