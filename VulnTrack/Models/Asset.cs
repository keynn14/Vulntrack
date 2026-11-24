namespace VulnTrack.Models;

public class Asset
{
    public string Id { get; set; } = "";
    public string Hostname { get; set; } = "";
    public string IpAddress { get; set; } = "";
    public string OperatingSystem { get; set; } = "";
    public string Owner { get; set; } = "";
    public string Team { get; set; } = "";
    public BusinessImpact Criticality { get; set; }
    public string Environment { get; set; } = "Production";
    public DateOnly LastScanned { get; set; }
    public string BusinessImpactNotes { get; set; } = "";
}
