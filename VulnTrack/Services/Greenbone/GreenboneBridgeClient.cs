using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;

namespace VulnTrack.Services.Greenbone;

public sealed class GreenboneBridgeOptions
{
    public const string SectionName = "GreenboneBridge";

    public string BaseUrl { get; set; } = "http://localhost:8085/";
    public string ApiKey { get; set; } = string.Empty;
    public int TimeoutSeconds { get; set; } = 60;
    public int MaxRetries { get; set; } = 3;
    public int PollIntervalSeconds { get; set; } = 15;
}

public sealed record StartScanResponse(
    [property: JsonPropertyName("task_id")] string TaskId,
    [property: JsonPropertyName("report_id")] string ReportId
);

public sealed record ScanStatusResponse(
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("progress")] string Progress
);

public sealed class GreenboneBridgeClient
{
    private readonly HttpClient _http;
    private readonly GreenboneBridgeOptions _options;
    private readonly ILogger<GreenboneBridgeClient> _logger;

    public GreenboneBridgeClient(
        HttpClient http,
        IOptions<GreenboneBridgeOptions> options,
        ILogger<GreenboneBridgeClient> logger)
    {
        _http = http;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<(bool Ok, string Message)> TestConnectionAsync(CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(_options.BaseUrl))
            return (false, "GreenboneBridge:BaseUrl is not configured.");

        try
        {
            using var resp = await SendWithRetryAsync(() => new HttpRequestMessage(HttpMethod.Get, "health"), ct);
            if (resp.IsSuccessStatusCode)
            {
                return (true, $"Connected to Greenbone bridge at {_options.BaseUrl}.");
            }
            return (false, $"Bridge returned HTTP {(int)resp.StatusCode} ({resp.ReasonPhrase}).");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Greenbone bridge health check failed for {BaseUrl}", _options.BaseUrl);
            return (false, $"Could not reach Greenbone bridge at {_options.BaseUrl}: {ex.Message}");
        }
    }

    public async Task<StartScanResponse> StartScanAsync(string name, IReadOnlyList<string> hosts, CancellationToken ct = default)
    {
        using var resp = await SendWithRetryAsync(() => new HttpRequestMessage(HttpMethod.Post, "scans")
        {
            Content = JsonContent.Create(new { name, hosts })
        }, ct);

        resp.EnsureSuccessStatusCode();
        var data = await resp.Content.ReadFromJsonAsync<StartScanResponse>(cancellationToken: ct)
                   ?? throw new InvalidOperationException("Bridge returned empty response from POST /scans.");
        return data;
    }

    public async Task<ScanStatusResponse> GetStatusAsync(string taskId, CancellationToken ct = default)
    {
        using var resp = await SendWithRetryAsync(() => new HttpRequestMessage(HttpMethod.Get, $"scans/{Uri.EscapeDataString(taskId)}"), ct);
        resp.EnsureSuccessStatusCode();
        return await resp.Content.ReadFromJsonAsync<ScanStatusResponse>(cancellationToken: ct)
               ?? new ScanStatusResponse("Unknown", "0");
    }

    public async Task<string> GetReportXmlAsync(string reportId, CancellationToken ct = default)
    {
        using var resp = await SendWithRetryAsync(() => new HttpRequestMessage(HttpMethod.Get, $"reports/{Uri.EscapeDataString(reportId)}"), ct);
        resp.EnsureSuccessStatusCode();
        return await resp.Content.ReadAsStringAsync(ct);
    }

    private async Task<HttpResponseMessage> SendWithRetryAsync(Func<HttpRequestMessage> factory, CancellationToken ct)
    {
        var maxAttempts = Math.Max(1, _options.MaxRetries);
        Exception? lastError = null;

        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var req = factory();
                if (!string.IsNullOrEmpty(_options.ApiKey))
                {
                    req.Headers.TryAddWithoutValidation("X-Api-Key", _options.ApiKey);
                }

                var resp = await _http.SendAsync(req, ct);
                if ((int)resp.StatusCode < 500 || attempt == maxAttempts)
                {
                    return resp;
                }
                resp.Dispose();
            }
            catch (HttpRequestException ex) when (attempt < maxAttempts)
            {
                lastError = ex;
                _logger.LogWarning("Greenbone bridge attempt {Attempt}/{Max} failed; retrying.", attempt, maxAttempts);
            }
            catch (TaskCanceledException ex) when (!ct.IsCancellationRequested && attempt < maxAttempts)
            {
                lastError = ex;
                _logger.LogWarning("Greenbone bridge attempt {Attempt}/{Max} timed out; retrying.", attempt, maxAttempts);
            }

            await Task.Delay(TimeSpan.FromMilliseconds(400 * attempt), ct);
        }

        throw lastError ?? new HttpRequestException("Greenbone bridge request failed after retries.");
    }
}
