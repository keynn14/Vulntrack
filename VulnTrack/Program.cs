using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using VulnTrack.Components;
using VulnTrack.Data;
using VulnTrack.Data.Entities;
using VulnTrack.Services;
using VulnTrack.Services.Auth;
using VulnTrack.Services.Greenbone;

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

builder.Services.AddDbContextFactory<AppDbContext>(options =>
    options.UseSqlServer(connectionString));
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
    await DbSeeder.SeedAsync(app.Services);
}

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapStaticAssets();
app.MapVulnTrackAuth();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
