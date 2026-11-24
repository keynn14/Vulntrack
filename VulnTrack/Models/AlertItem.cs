namespace VulnTrack.Models;

public class AlertItem
{
    public string Id { get; set; } = "";
    public string Title { get; set; } = "";
    public string Message { get; set; } = "";
    public Severity Severity { get; set; }
    public AlertType Type { get; set; } = AlertType.SlaOverdue;
    public DateTime CreatedAt { get; set; }
    public bool IsRead { get; set; }
    public string Link { get; set; } = "/vulnerabilities";
}
