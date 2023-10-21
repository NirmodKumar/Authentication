using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;

const string AuthScheme = "cookie";

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(AuthScheme)
    .AddCookie(AuthScheme);

builder.Services.AddAuthorization(auth =>
{
    auth.AddPolicy("passport_ind", pb =>
    {
        pb.RequireAuthenticatedUser()
        .AddAuthenticationSchemes(AuthScheme)
        .RequireClaim("passport_type", "ind");
    });
    auth.AddPolicy("passport_usa", pb =>
    {
        pb.RequireAuthenticatedUser()
        .AddAuthenticationSchemes(AuthScheme)
        .RequireClaim("passport_type", "usa");
    });
    auth.AddPolicy("passport_uae", pb =>
    {
        pb.RequireAuthenticatedUser()
        .AddAuthenticationSchemes(AuthScheme)
        .RequireClaim("passport_type", "uae");
    });

    auth.AddPolicy("Custom-Authorization-Workflow", pb =>
    {
        pb.RequireAuthenticatedUser();
    });
});

var app = builder.Build();

app.UseAuthentication();

app.Use((ctx, next) =>
{
    //if (ctx.Request.Path.StartsWithSegments("/login"))
    //{
    //    return next();
    //}
    //if (!ctx.User.Identities.Any(x => x.AuthenticationType == AuthScheme))
    //{
    //    ctx.Response.StatusCode = 401;
    //    return Task.CompletedTask;
    //}
    //if (!ctx.User.HasClaim("passport_type", "ind"))
    //{
    //    ctx.Response.StatusCode = 403;
    //    return Task.CompletedTask;
    //}

    return next();
});

app.MapGet("/unsecure", (HttpContext ctx) =>
{
    var usr = ctx.User.FindFirst("usr")?.Value ?? "empty";
    return usr;
}).RequireAuthorization("passport_ind");

app.MapGet("/india", (HttpContext ctx) =>
{
    return "allowed";
}).RequireAuthorization("passport_ind");

app.MapGet("/usa", (HttpContext ctx) =>
{
    return "allowed";
}).RequireAuthorization("passport_usa"); ;

app.MapGet("/uae", (HttpContext ctx) =>
{
    return "allowed";
}).RequireAuthorization("passport_uae"); ;

app.MapGet("/login", async (HttpContext ctx) =>
{
    var claims = new List<Claim>();
    claims.Add(new Claim("usr", "nirmod"));
    claims.Add(new Claim("passport_type", "ind"));
    var identity = new ClaimsIdentity(claims, AuthScheme);
    var usr = new ClaimsPrincipal(identity);
    await ctx.SignInAsync(AuthScheme, usr);
    return "SignIn";
}).AllowAnonymous();

app.MapGet("/logout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync(AuthScheme);
    return "SignOut";
}).AllowAnonymous();

app.Run();


public class MyAuthorizationRequirement : IAuthorizationRequirement
{
    public MyAuthorizationRequirement()
    {
    }
}

public class MyRequirementHandler : AuthorizationHandler<MyAuthorizationRequirement>
{
    public MyRequirementHandler()
    {

    }
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, MyAuthorizationRequirement requirement)
    {

        return Task.CompletedTask;
    }
}