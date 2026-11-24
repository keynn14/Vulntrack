using Microsoft.AspNetCore.Identity;
using VulnTrack.Data;
using VulnTrack.Data.Entities;

namespace VulnTrack.Services.Auth;

public static class AuthEndpoints
{
    public static void MapVulnTrackAuth(this WebApplication app)
    {
        app.MapPost("/auth/login", async (
            HttpContext http,
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            AppDbContext db) =>
        {
            var form = await http.Request.ReadFormAsync();
            var email = form["email"].ToString().Trim();
            var password = form["password"].ToString();
            var returnUrl = form["returnUrl"].ToString();

            if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
            {
                return Results.LocalRedirect("/login?error=missing");
            }

            var user = await userManager.FindByEmailAsync(email) ?? await userManager.FindByNameAsync(email);
            if (user is null)
            {
                return Results.LocalRedirect("/login?error=invalid");
            }

            if (!user.IsActive)
            {
                return Results.LocalRedirect("/login?error=disabled");
            }

            var result = await signInManager.PasswordSignInAsync(user, password, isPersistent: true, lockoutOnFailure: false);
            if (!result.Succeeded)
            {
                return Results.LocalRedirect("/login?error=invalid");
            }

            user.LastLoginAt = DateTime.UtcNow;
            db.AuditLogs.Add(new AuditLogEntity
            {
                UserId = user.Id,
                Action = "UserSignedIn",
                TargetType = "User",
                TargetId = user.Id,
                Details = $"Signed in as {user.Email}",
                IpAddress = http.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1",
                Timestamp = DateTime.UtcNow
            });
            await db.SaveChangesAsync();

            var target = !string.IsNullOrWhiteSpace(returnUrl)
                         && returnUrl.StartsWith('/')
                         && !returnUrl.StartsWith("//")
                         && !returnUrl.StartsWith("/\\")
                ? returnUrl
                : "/dashboard";

            return Results.LocalRedirect(target);
        }).AllowAnonymous();

        app.MapGet("/auth/logout", async (
            HttpContext http,
            SignInManager<ApplicationUser> signInManager,
            AppDbContext db) =>
        {
            var userId = http.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            if (!string.IsNullOrEmpty(userId))
            {
                db.AuditLogs.Add(new AuditLogEntity
                {
                    UserId = userId,
                    Action = "UserSignedOut",
                    TargetType = "User",
                    TargetId = userId,
                    Details = "User signed out",
                    IpAddress = http.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1",
                    Timestamp = DateTime.UtcNow
                });
                await db.SaveChangesAsync();
            }

            await signInManager.SignOutAsync();
            return Results.LocalRedirect("/login");
        }).AllowAnonymous();
    }
}
