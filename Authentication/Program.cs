using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDataProtection();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<AuthService>();

var app = builder.Build();

app.Use((ctx, next) =>
{
    var idp = ctx.RequestServices.GetRequiredService<IDataProtectionProvider>();
    var protector = idp.CreateProtector("auth-cookie");
    var authCookie = ctx.Request.Headers.Cookie.FirstOrDefault(x => x.Contains("auth="));
    if (authCookie != null)
    {
        var payload = authCookie?.Split("=").Last();
        var unProtectPayload = protector.Unprotect(payload ?? "");
        var parts = unProtectPayload.Split(':');
        var key = parts[0];
        var value = parts[1];

        var claims = new List<Claim>();
        claims.Add(new Claim(key, value));
        var identity = new ClaimsIdentity(claims);
        ctx.User = new ClaimsPrincipal(identity);
    }
    return next();
});

app.MapGet("/username", (HttpContext ctx) =>
{
    var usr = ctx.User.FindFirst("usr").Value;
    return usr;
});

app.MapGet("/login", (AuthService auth) =>
{
    auth.SignIn();
    return "ok";
});

app.Run();

public class AuthService
{
    private readonly IHttpContextAccessor _context;
    private readonly IDataProtectionProvider _idp;

    public AuthService(IHttpContextAccessor context, IDataProtectionProvider idp)
    {
        _context = context;
        _idp = idp;
    }

    public void SignIn()
    {
        var protector = _idp.CreateProtector("auth-cookie");
        _context.HttpContext.Response.Headers["Set-Cookie"] = $"auth={protector.Protect("usr:nirmod")}";
    }
}