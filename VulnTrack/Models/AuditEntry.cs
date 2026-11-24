namespace VulnTrack.Models;

public class AuditEntry
{
    public string Id { get; set; } = "";
    public DateTime Timestamp { get; set; }
    public string Actor { get; set; } = "";
    public string Action { get; set; } = "";
    public string ActionType { get; set; } = "Security";
    public string Target { get; set; } = "";
    public string Details { get; set; } = "";
    public string IpAddress { get; set; } = "10.20.1.14";
}
