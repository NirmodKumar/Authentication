using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

const string AuthScheme = "cookie";

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(AuthScheme)
    .AddCookie(AuthScheme);

var app = builder.Build();

app.UseAuthentication();

app.MapGet("/username", (HttpContext ctx) =>
{
    var usr = ctx.User.FindFirst("usr")?.Value ?? "empty";
    return usr;
});

app.MapGet("/login", async (HttpContext ctx) =>
{
    var claims = new List<Claim>();
    claims.Add(new Claim("usr", "nirmod"));
    var identity = new ClaimsIdentity(claims, AuthScheme);
    var usr = new ClaimsPrincipal(identity);
    await ctx.SignInAsync(AuthScheme, usr);
    return "ok";
});

app.Run();