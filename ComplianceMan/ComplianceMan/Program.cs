
using AutoMapper;
using ComplianceMan.Common.Models;
using ComplianceMan.Data;
using ComplianceMan.Data.Entity;
using ComplianceMan.Data.Interfaces;
using ComplianceMan.Data.Repositories;
using ComplianceMan.Services.Interfaces;
using ComplianceMan.Services.Mapper;
using ComplianceMan.Services.Services;
using ComplianceMan.Shared;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using Auth0.AspNetCore.Authentication;
using System.IdentityModel.Tokens.Jwt;
using Milbix.OAuthConnector.Core.Model;
using Milbix.OAuthConnector.Core.Interface;
using Milbix.OAuthConnector.Core.Service;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();
builder.Services.AddDbContextFactory<ComplianceManDbContext>(option=>
option.UseSqlServer(builder.Configuration.GetConnectionString("Default")));


builder.Services.AddScoped<ITeamService, TeamService>();
builder.Services.AddScoped<IUserService, UserService>();

builder.Services.AddScoped<IPolicyService, PolicyService>();
builder.Services.AddScoped<IRoleService, RoleService>();
builder.Services.AddScoped<IUserPolicyService, UserPolicyService>();
builder.Services.AddScoped<IFileService, FileService>();

builder.Services.AddScoped<ITeamRepository, TeamRepository>();
builder.Services.AddScoped<IUserRepository, UserRepository>();

builder.Services.AddScoped<IFileRepository, FileRepository>();


builder.Services.AddScoped<IPolicyRepository, PolicyRepository>();
builder.Services.AddScoped<IUserPolicyRepository, UserPolicyRepository>();
builder.Services.AddScoped<IRoleRepository, RoleRepository>();
builder.Services.AddScoped<StateContainer>();

builder.Services.Configure<AuthenticationConfig>(builder.Configuration.GetSection("Authentication:AzureAD"));
builder.Services.AddScoped<IAzureAdAuthenticationService, AzureAdAuthenticationService>();

// Register AutoMapper
// Create AutoMapper configuration
var mapperConfig = new MapperConfiguration(cfg =>
{
    cfg.AddProfile(new AutoMapperProfile());
});

// Create IMapper instance
var mapper = mapperConfig.CreateMapper();

// Register the IMapper instance with DI
builder.Services.AddSingleton(mapper);

var selectedOAuthProvider = builder.Configuration["OAuthProvider:Name"];

if (!string.IsNullOrEmpty(selectedOAuthProvider) && selectedOAuthProvider == "Auth0")
{
    builder.Services
        .AddAuth0WebAppAuthentication(options =>
        {
            options.Domain = builder.Configuration["Auth0:Domain"];
            options.ClientId = builder.Configuration["Auth0:ClientId"];
            options.Scope = "openid profile email";
        });

}
else
{
    var authProviders = builder.Configuration.GetSection("AuthProviders").GetChildren();

    builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = "CombinedAuth";
    })
    .AddCookie();

    foreach (var provider in authProviders)
    {
        var providerType = provider["ProviderType"];
        var providerName = provider.Key;

        if (providerType == "OpenIDConnect")
        {
            if (!string.IsNullOrEmpty(providerName) && providerName == "AzureAD")
            {
                builder.Services.AddAuthentication().AddOpenIdConnect("AzureAD", "Azure AD", options =>
                {
                    builder.Configuration.GetSection("AuthProviders").GetSection(providerName).Bind(options);
                });

            }

            if (!string.IsNullOrEmpty(providerName) && providerName == "Milbix")
            {
                builder.Services.AddAuthentication().AddOpenIdConnect("Milbix", "Milbix", options =>
                {
                    // this is my Authorization Server Port
                    options.Authority = "https://localhost:7275";
                    options.ClientId = "milbix.OAuth.Milbix.MVC";
                    options.ClientSecret = "987654321";
                    options.ResponseType = "code";
                    options.CallbackPath = "/signin-oidc";
                    options.SaveTokens = true;
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = false,
                        SignatureValidator = delegate (string token, TokenValidationParameters validationParameters)
                        {
                            var jwt = new JwtSecurityToken(token);
                            return jwt;
                        },
                    };


                });

            }
        }

        else if (providerType == "Google")
        {
            builder.Services.AddAuthentication().AddGoogle(options =>
            {
                builder.Configuration.GetSection("AuthProviders").GetSection(providerName).Bind(options);
            });
        }

        else if (providerType == "OAuth")
        {
            builder.Services.AddAuthentication().AddOAuth(providerName, options =>
            {
                builder.Configuration.GetSection("AuthProviders").GetSection(providerName).Bind(options);
                options.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
                options.TokenEndpoint = "https://github.com/login/oauth/access_token";
                options.UserInformationEndpoint = "https://api.github.com/user";
                options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "id");
                options.ClaimActions.MapJsonKey(ClaimTypes.Name, "login");
                options.ClaimActions.MapJsonKey("urn:github:avatar", "avatar_url");
            });
        }

        //else if (providerType == "Auth0")
        //{
        //    builder.Services.AddAuthentication().AddAuth0WebAppAuthentication(options =>
        //    {
        //        options.Domain = builder.Configuration["AuthProviders:Auth0:Domain"];
        //        options.ClientId = builder.Configuration["AuthProviders:Auth0:ClientId"];
        //        options.Scope = "openid profile email";
        //    });
        //}

        // Add more conditions for other provider types

        // Configure callback path based on provider name
        var callbackPath = provider["CallbackPath"];
        if (!string.IsNullOrEmpty(callbackPath))
        {
            builder.Services.Configure<OpenIdConnectOptions>(providerName, options =>
            {
                options.CallbackPath = callbackPath;
            });
        }
    }

    builder.Services.AddAuthentication().AddScheme<RemoteAuthenticationOptions, CombinedAuthenticationHandler>("CombinedAuth", options =>
    {
        options.CallbackPath = "/signin-combined";
    });

}



builder.Services.AddHttpContextAccessor();


builder.Services.AddScoped<IOAuthConnector>(provider =>
{
    var configuration = provider.GetRequiredService<IConfiguration>();

    var providerName = configuration["OAuthProvider:Name"];
    var clientId = configuration[$"{providerName}:ClientId"];
    var clientSecret = configuration[$"{providerName}:ClientSecret"];
    var redirectUri = configuration[$"{providerName}:CallbackPath"];
    var authority = configuration[$"{providerName}:Authority"];
    var scopes = configuration[$"{providerName}:Scopes"];

    return new OAuthConnector(clientId, clientSecret, redirectUri, authority, scopes);
});



var app = builder.Build();

await EnsureDatabaseIsMigrated(app.Services);

async Task EnsureDatabaseIsMigrated(IServiceProvider services)
{
    using var scope = services.CreateScope();
    using var context = scope.ServiceProvider.GetService<ComplianceManDbContext>();
 
      await context.Database.MigrateAsync();


}

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

//app.MapBlazorHub();
//app.MapFallbackToPage("/_Host");

app.UseEndpoints(endpoints =>
{
    endpoints.MapControllers();
    endpoints.MapBlazorHub();
    endpoints.MapFallbackToPage("/_Host");
});

app.Run();
