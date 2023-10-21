using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

const string AuthScheme = "cookie";

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(AuthScheme)
    .AddCookie(AuthScheme);

var app = builder.Build();

app.UseAuthentication();

app.MapGet("/unsecure", (HttpContext ctx) =>
{
    var usr = ctx.User.FindFirst("usr")?.Value ?? "empty";
    return usr;
});

app.MapGet("/india", (HttpContext ctx) =>
{
    if (!ctx.User.Identities.Any(x => x.AuthenticationType == AuthScheme))
    {
        ctx.Response.StatusCode = 401;
        return "";
    }
    if (!ctx.User.HasClaim("passport_type", "ind"))
    {
        ctx.Response.StatusCode = 403;
        return "";
    }

    return "allowed";
});

app.MapGet("/usa", (HttpContext ctx) =>
{
    if (!ctx.User.Identities.Any(x => x.AuthenticationType == AuthScheme))
    {
        ctx.Response.StatusCode = 401;
        return "";
    }
    if (!ctx.User.HasClaim("passport_type", "usa"))
    {
        ctx.Response.StatusCode = 403;
        return "";
    }

    return "allowed";
});

app.MapGet("/uae", (HttpContext ctx) =>
{
    if (!ctx.User.Identities.Any(x => x.AuthenticationType == AuthScheme))
    {
        ctx.Response.StatusCode = 401;
        return "";
    }
    if (!ctx.User.HasClaim("passport_type", "uae"))
    {
        ctx.Response.StatusCode = 403;
        return "";
    }

    return "allowed";
});

app.MapGet("/login", async (HttpContext ctx) =>
{
    var claims = new List<Claim>();
    claims.Add(new Claim("usr", "nirmod"));
    claims.Add(new Claim("passport_type", "ind"));
    var identity = new ClaimsIdentity(claims, AuthScheme);
    var usr = new ClaimsPrincipal(identity);
    await ctx.SignInAsync(AuthScheme, usr);
    return "SignIn";
});

app.MapGet("/logout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync(AuthScheme);
    return "SignOut";
});

app.Run();