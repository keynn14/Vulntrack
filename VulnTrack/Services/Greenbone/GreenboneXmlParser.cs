using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using VulnTrack.Data.Entities;

namespace VulnTrack.Services.Greenbone;

public sealed class GreenboneXmlParser : IGreenboneReportParser
{
    private static readonly Regex Ipv4Regex = new(@"^\d{1,3}(\.\d{1,3}){3}$", RegexOptions.Compiled);

    public async Task<ParseResult> ParseXmlAsync(Stream xmlStream, bool includeInfoLevel, CancellationToken ct = default)
    {
        if (xmlStream is null || !xmlStream.CanRead)
            throw new InvalidDataException("Scan file stream is empty or unreadable.");

        var findings = new List<ParsedFinding>();
        var warnings = new List<string>();
        var sawReportElement = false;

        // XXE protection: prohibit DTD processing and external entity resolution.
        var settings = new XmlReaderSettings
        {
            Async = true,
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            IgnoreComments = true,
            IgnoreProcessingInstructions = true,
            MaxCharactersInDocument = 60_000_000
        };

        try
        {
            using var reader = XmlReader.Create(xmlStream, settings);
            while (await reader.ReadAsync())
            {
                ct.ThrowIfCancellationRequested();

                if (reader.NodeType != XmlNodeType.Element) continue;

                if (reader.LocalName.Equals("report", StringComparison.OrdinalIgnoreCase))
                {
                    sawReportElement = true;
                    continue;
                }

                if (!reader.LocalName.Equals("result", StringComparison.OrdinalIgnoreCase)) continue;

                // Stream one <result> subtree at a time so 50 MB reports keep memory bounded.
                if (XNode.ReadFrom(reader) is not XElement resultEl) continue;

                var parsed = ParseResultElement(resultEl, includeInfoLevel, warnings);
                if (parsed is not null)
                {
                    findings.Add(parsed);
                }
            }
        }
        catch (XmlException ex)
        {
            throw new InvalidDataException($"Malformed Greenbone XML at line {ex.LineNumber}, position {ex.LinePosition}: {ex.Message}", ex);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is not InvalidDataException)
        {
            throw new InvalidDataException($"Failed to parse Greenbone XML report: {ex.Message}", ex);
        }

        if (!sawReportElement && findings.Count == 0)
        {
            throw new InvalidDataException("XML file does not appear to be a valid Greenbone report (missing <report> or <result> elements).");
        }

        return new ParseResult(findings, warnings);
    }

    public async Task<ParseResult> ParseCsvAsync(Stream csvStream, bool includeInfoLevel, CancellationToken ct = default)
    {
        var findings = new List<ParsedFinding>();
        var warnings = new List<string>();

        using var reader = new StreamReader(csvStream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: true);
        var headerLine = await reader.ReadLineAsync(ct);
        if (string.IsNullOrWhiteSpace(headerLine))
            throw new InvalidDataException("CSV scan file is empty.");

        var headers = SplitCsvLine(headerLine).Select(h => h.Trim().ToLowerInvariant()).ToList();
        int Col(params string[] names)
        {
            foreach (var n in names)
            {
                var idx = headers.IndexOf(n);
                if (idx >= 0) return idx;
            }
            return -1;
        }

        var iIp = Col("ip", "ipaddress", "ip address");
        var iHost = Col("hostname", "host", "asset");
        var iPort = Col("port");
        var iProto = Col("port protocol", "protocol");
        var iCvss = Col("cvss", "cvssscore", "cvss score");
        var iSev = Col("severity", "threat");
        var iTitle = Col("nvt name", "title", "name");
        var iOid = Col("nvt oid", "oid");
        var iCve = Col("cves", "cve", "cveid", "cve id");
        var iDesc = Col("summary", "description", "specific result");
        var iFix = Col("solution", "recommendedfix", "recommended fix");

        if (iIp < 0 && iHost < 0)
            throw new InvalidDataException("CSV header must include an IP or Hostname column.");

        var lineNo = 1;
        while (await reader.ReadLineAsync(ct) is { } line)
        {
            ct.ThrowIfCancellationRequested();
            lineNo++;
            if (string.IsNullOrWhiteSpace(line)) continue;

            var cols = SplitCsvLine(line);
            string Get(int idx) => idx >= 0 && idx < cols.Count ? cols[idx].Trim() : string.Empty;

            var ip = Get(iIp);
            var host = Get(iHost);
            if (string.IsNullOrWhiteSpace(host)) host = ip;
            if (string.IsNullOrWhiteSpace(ip)) ip = host;
            if (string.IsNullOrWhiteSpace(host))
            {
                warnings.Add($"CSV line {lineNo} skipped: missing host/IP.");
                continue;
            }

            var (port, parsedProto) = ParsePort(Get(iPort));
            var proto = string.IsNullOrWhiteSpace(Get(iProto)) ? parsedProto : Get(iProto).ToLowerInvariant();
            var cvssText = Get(iCvss);
            decimal.TryParse(cvssText, NumberStyles.Any, CultureInfo.InvariantCulture, out var cvss);
            cvss = Math.Clamp(Math.Round(cvss, 1), 0.0m, 10.0m);

            var threat = Get(iSev);
            var severity = MapSeverity(cvss, threat);
            if (!includeInfoLevel && severity == VulnerabilitySeverity.Info) continue;

            var oid = Get(iOid);
            var title = Get(iTitle);
            var cves = Get(iCve)
                .Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries)
                .Where(c => !c.Equals("NOCVE", StringComparison.OrdinalIgnoreCase))
                .ToList();

            var cveId = cves.Count > 0
                ? cves[0].ToUpperInvariant()
                : (!string.IsNullOrWhiteSpace(oid) ? $"NVT-{oid}" : $"NVT-{Math.Abs(title.GetHashCode()) % 999999}");

            if (cveId.Length > 32) cveId = cveId[..32];
            if (string.IsNullOrWhiteSpace(title)) title = cveId;
            if (title.Length > 250) title = title[..250];

            findings.Add(new ParsedFinding(
                CveId: cveId,
                Title: title,
                Description: Get(iDesc),
                Severity: severity,
                CvssScore: cvss,
                Hostname: host,
                IpAddress: ip,
                Port: port,
                Protocol: proto,
                Service: InferService(port, proto),
                RecommendedFix: string.IsNullOrWhiteSpace(Get(iFix))
                    ? "Apply vendor security updates and confirm remediation with a rescan."
                    : Get(iFix),
                NvtOid: oid
            ));
        }

        return new ParseResult(findings, warnings);
    }

    private static ParsedFinding? ParseResultElement(XElement r, bool includeInfoLevel, List<string> warnings)
    {
        var threat = r.Element("threat")?.Value?.Trim();
        var nvt = r.Element("nvt");
        var oid = nvt?.Attribute("oid")?.Value?.Trim() ?? string.Empty;

        var cvssRaw = r.Element("severity")?.Value?.Trim()
                      ?? nvt?.Element("cvss_base")?.Value?.Trim()
                      ?? "0";
        decimal.TryParse(cvssRaw, NumberStyles.Any, CultureInfo.InvariantCulture, out var cvss);
        cvss = Math.Clamp(Math.Round(cvss, 1), 0.0m, 10.0m);

        var severity = MapSeverity(cvss, threat);
        if (!includeInfoLevel && (severity == VulnerabilitySeverity.Info ||
                                  string.Equals(threat, "Log", StringComparison.OrdinalIgnoreCase)))
        {
            return null;
        }

        var hostEl = r.Element("host");
        var directHostText = hostEl?.Nodes().OfType<XText>().FirstOrDefault()?.Value?.Trim() ?? string.Empty;
        var hostnameEl = hostEl?.Element("hostname")?.Value?.Trim() ?? string.Empty;

        var ip = Ipv4Regex.IsMatch(directHostText) ? directHostText : (!string.IsNullOrWhiteSpace(directHostText) ? directHostText : hostnameEl);
        var hostname = !string.IsNullOrWhiteSpace(hostnameEl) ? hostnameEl : directHostText;

        if (string.IsNullOrWhiteSpace(hostname) && string.IsNullOrWhiteSpace(ip))
        {
            warnings.Add($"Skipped <result> (NVT {oid}): missing <host>.");
            return null;
        }

        if (string.IsNullOrWhiteSpace(hostname)) hostname = ip;
        if (string.IsNullOrWhiteSpace(ip)) ip = hostname;

        var (port, protocol) = ParsePort(r.Element("port")?.Value);

        // Extract first CVE reference from <nvt><refs><ref type="cve" id="..."/> or legacy <nvt><cve>
        var cveList = nvt?.Element("refs")?.Elements("ref")
            .Where(x => string.Equals(x.Attribute("type")?.Value, "cve", StringComparison.OrdinalIgnoreCase))
            .Select(x => x.Attribute("id")?.Value?.Trim())
            .Where(id => !string.IsNullOrWhiteSpace(id) && !id!.Equals("NOCVE", StringComparison.OrdinalIgnoreCase))
            .ToList() ?? new List<string?>();

        if (cveList.Count == 0)
        {
            var legacy = nvt?.Element("cve")?.Value?.Trim();
            if (!string.IsNullOrWhiteSpace(legacy) && !legacy.Equals("NOCVE", StringComparison.OrdinalIgnoreCase))
            {
                cveList.AddRange(legacy.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries));
            }
        }

        var cveId = cveList.Count > 0
            ? cveList[0]!.ToUpperInvariant()
            : (!string.IsNullOrWhiteSpace(oid) ? $"NVT-{oid}" : $"NVT-{Math.Abs((r.Element("name")?.Value ?? "FINDING").GetHashCode()) % 999999}");

        if (cveId.Length > 32) cveId = cveId[..32];

        var title = (r.Element("name")?.Value ?? nvt?.Element("name")?.Value ?? cveId).Trim();
        if (title.Length > 250) title = title[..250];

        var description = r.Element("description")?.Value?.Trim() ?? string.Empty;
        if (cveList.Count > 1)
        {
            var extras = string.Join(", ", cveList.Skip(1));
            description = string.IsNullOrWhiteSpace(description)
                ? $"Additional CVEs: {extras}"
                : $"{description}\nAdditional CVEs: {extras}";
        }

        var solution = nvt?.Element("solution")?.Value?.Trim();
        if (string.IsNullOrWhiteSpace(solution))
        {
            solution = "Apply vendor security updates and verify remediation with a Greenbone rescan.";
        }

        return new ParsedFinding(
            CveId: cveId,
            Title: title,
            Description: description,
            Severity: severity,
            CvssScore: cvss,
            Hostname: hostname,
            IpAddress: ip,
            Port: port,
            Protocol: protocol,
            Service: InferService(port, protocol),
            RecommendedFix: solution,
            NvtOid: oid
        );
    }

    private static VulnerabilitySeverity MapSeverity(decimal cvss, string? threat)
    {
        if (cvss >= 9.0m) return VulnerabilitySeverity.Critical;
        if (cvss >= 7.0m) return VulnerabilitySeverity.High;
        if (cvss >= 4.0m) return VulnerabilitySeverity.Medium;
        if (cvss > 0.0m) return VulnerabilitySeverity.Low;

        return threat?.Trim().ToLowerInvariant() switch
        {
            "critical" => VulnerabilitySeverity.Critical,
            "high" => VulnerabilitySeverity.High,
            "medium" => VulnerabilitySeverity.Medium,
            "low" => VulnerabilitySeverity.Low,
            _ => VulnerabilitySeverity.Info
        };
    }

    private static (int Port, string Protocol) ParsePort(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return (0, "tcp");
        var parts = raw.Trim().Split('/');
        var proto = parts.Length > 1 && !string.IsNullOrWhiteSpace(parts[1]) ? parts[1].Trim().ToLowerInvariant() : "tcp";
        return int.TryParse(parts[0].Trim(), out var port)
            ? (Math.Clamp(port, 0, 65535), proto)
            : (0, proto);
    }

    private static string InferService(int port, string protocol) => port switch
    {
        22 => "ssh",
        80 => "http",
        443 => "https",
        445 => "smb",
        3389 => "rdp",
        8080 => "http-alt",
        8443 => "https-alt",
        _ => protocol
    };

    private static List<string> SplitCsvLine(string line)
    {
        var list = new List<string>();
        var current = new StringBuilder();
        var inQuotes = false;
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (c == '"')
            {
                if (inQuotes && i + 1 < line.Length && line[i + 1] == '"')
                {
                    current.Append('"');
                    i++;
                }
                else
                {
                    inQuotes = !inQuotes;
                }
            }
            else if (c == ',' && !inQuotes)
            {
                list.Add(current.ToString());
                current.Clear();
            }
            else
            {
                current.Append(c);
            }
        }
        list.Add(current.ToString());
        return list;
    }
}
