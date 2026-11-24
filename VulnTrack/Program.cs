using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using VulnTrack.Components;
using VulnTrack.Data;
using VulnTrack.Data.Entities;
using VulnTrack.Services;
using VulnTrack.Services.Auth;
using VulnTrack.Services.Greenbone;

var builder = WebApplication.CreateBuilder(args);

var provider = builder.Configuration["DatabaseProvider"] ?? "SqlServer";
var sqlServerConn = builder.Configuration.GetConnectionString("DefaultConnection") ?? string.Empty;

// Automatically fall back to local SQLite if running in a container OR deployed on a remote Windows/IIS host
// while DefaultConnection still points to the developer's local SQLEXPRESS instance.
var isDevLaptopConn = sqlServerConn.Contains("LAPTOP-NQJNMVEP", StringComparison.OrdinalIgnoreCase)
                      && !string.Equals(Environment.MachineName, "LAPTOP-NQJNMVEP", StringComparison.OrdinalIgnoreCase);

var useSqlite = string.Equals(provider, "Sqlite", StringComparison.OrdinalIgnoreCase)
                || string.IsNullOrWhiteSpace(sqlServerConn)
                || isDevLaptopConn
                || (!OperatingSystem.IsWindows() && sqlServerConn.Contains("SQLEXPRESS", StringComparison.OrdinalIgnoreCase));

var sqliteConn = builder.Configuration.GetConnectionString("SqliteConnection");
if (useSqlite && string.IsNullOrWhiteSpace(sqliteConn))
{
    var dataDir = Path.Combine(builder.Environment.ContentRootPath, "App_Data");
    Directory.CreateDirectory(dataDir);
    sqliteConn = $"Data Source={Path.Combine(dataDir, "vulntrack.db")}";
}

builder.Services.AddDbContextFactory<AppDbContext>(options =>
{
    if (useSqlite)
    {
        options.UseSqlite(sqliteConn);
    }
    else
    {
        options.UseSqlServer(sqlServerConn);
    }
});

builder.Services.AddScoped(sp =>
    sp.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContext());

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
    {
        options.Password.RequireDigit = true;
        options.Password.RequiredLength = 8;
        options.Password.RequireUppercase = true;
        options.Password.RequireNonAlphanumeric = false;
        options.User.RequireUniqueEmail = true;
    })
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/login";
    options.LogoutPath = "/auth/logout";
    options.AccessDeniedPath = "/dashboard";
    options.SlidingExpiration = true;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
});

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
});

builder.Services.AddCascadingAuthenticationState();
builder.Services.AddAuthorization();

builder.Services.Configure<GreenboneBridgeOptions>(
    builder.Configuration.GetSection(GreenboneBridgeOptions.SectionName));

builder.Services.AddHttpClient<GreenboneBridgeClient>((sp, http) =>
{
    var opts = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<GreenboneBridgeOptions>>().Value;
    if (!string.IsNullOrWhiteSpace(opts.BaseUrl))
    {
        http.BaseAddress = new Uri(opts.BaseUrl);
    }
    http.Timeout = TimeSpan.FromSeconds(Math.Clamp(opts.TimeoutSeconds, 5, 300));
});

builder.Services.AddSingleton<IGreenboneReportParser, GreenboneXmlParser>();
builder.Services.AddScoped<IImportService, ImportService>();
builder.Services.AddSingleton<GreenboneScanQueue>();
builder.Services.AddHostedService<GreenboneScanBackgroundService>();
builder.Services.AddScoped<VulnTrackDataService>();

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

var app = builder.Build();

if (!EF.IsDesignTime)
{
    try
    {
        app.Logger.LogInformation("Initializing VulnTrack database using {Provider}...", useSqlite ? "SQLite" : "SQL Server");
        await DbSeeder.SeedAsync(app.Services);
    }
    catch (Exception ex)
    {
        // Log instead of crashing the worker process with HTTP 500.30 on IIS/App Service.
        app.Logger.LogError(ex, "Database initialization/seeding failed during startup.");
    }
}

app.UseForwardedHeaders();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);

if (app.Environment.IsDevelopment())
{
    app.UseHttpsRedirection();
}

app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapStaticAssets();
app.MapVulnTrackAuth();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
