using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation.AspNetCore;
using System.Security.Claims;
using TheIdentityServer.Data;
using TheIdentityServer.Data.Seed;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(connectionString);

    #region step1 : Add OpenId

    options.UseOpenIddict();
    #endregion
});


builder.Services.AddDatabaseDeveloperPageExceptionFilter();


#region step 2: AspNet Identity
//default:
//builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
//    .AddEntityFrameworkStores<ApplicationDbContext>();

//init aspnet identiy setting
builder.Services
    .AddIdentity<IdentityUser, IdentityRole>(
        options => options.SignIn.RequireConfirmedAccount = true
    )
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultUI()
    .AddDefaultTokenProviders();


//data protection provider setting
builder.Services.Configure<DataProtectionTokenProviderOptions>(opt =>
    opt.TokenLifespan = TimeSpan.FromHours(1));

//identity setting
builder.Services.Configure<IdentityOptions>(options =>
{
    //https://pierodetomi.medium.com/oauth-authentication-with-individual-user-accounts-on-asp-net-core-2-2-31a884c3dbfb

    // Configure Identity to use the same JWT claims as OpenIddict instead
    // of the legacy WS-Federation claims it uses by default (ClaimTypes),
    // which saves you from doing the mapping in your authorization controller.
    options.ClaimsIdentity.UserNameClaimType = Claims.Name;
    options.ClaimsIdentity.UserIdClaimType = Claims.Subject;
    options.ClaimsIdentity.RoleClaimType = Claims.Role;
    options.ClaimsIdentity.EmailClaimType = Claims.Email;

    //Note: to require account confirmation befor login,
    //register an email sender service (IEmailSender) and
    //set options.SignIn.RequireConfirmedAccount to true
    //
    // For more information, visit https://aka.ms/aspaccountconf.
    options.SignIn.RequireConfirmedAccount = false;

    //password settings. The setting can be set from config
    options.Password.RequireDigit = false; //configuration.GetValue<bool>("PasswordSettings:RequireDigit")
    options.Password.RequireLowercase = false;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = false;
    options.Password.RequiredLength = 6;
    options.Password.RequiredUniqueChars = 0;

    //lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    //user settings
    options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
    options.User.RequireUniqueEmail = true;
});


//cookie setting
builder.Services.ConfigureApplicationCookie(options =>
{
    //cookie settings
    options.Cookie.HttpOnly = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(5);

    options.LoginPath = "/Identity/Account/Login";
    options.AccessDeniedPath = "/Identity/Account/AccessDenied";
    options.SlidingExpiration = true;

});


#endregion

# region OpenId

builder.Services.AddOpenIddict()

    //Register the OpenIddict core components.
    .AddCore(options =>
    {
        // Configure OpenIddict to use the Entity Framework Core store.
        // Note: call ReplaceDefaultEntities() to replace the default entities
        options.UseEntityFrameworkCore()
            .UseDbContext<ApplicationDbContext>();
    })

    //Register the OpenIddict server components.
    .AddServer(options =>
    {
        // Enable the authorization, logout, token and userinfo endpoint
        options.SetAuthorizationEndpointUris("/connect/authorize")
            .SetLogoutEndpointUris("/connect/logout")
            .SetTokenEndpointUris("/connect/token")
            .SetUserinfoEndpointUris("/connect/userinfo")
            .SetIntrospectionEndpointUris("/connect/introspect")
            .SetVerificationEndpointUris("/connect/verify");

        // Mark the email, profile and roles scope as supported scopes.
        options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles);

        // Enable the client credential flow
        options.AllowClientCredentialsFlow()
            .AllowAuthorizationCodeFlow()
            .AllowRefreshTokenFlow()
            .RequireProofKeyForCodeExchange();

        // Register the signing and encryption credentials.
        options.AddDevelopmentEncryptionCertificate()
            .AddDevelopmentSigningCertificate();

        // Register the ASP.NET Core host and configure the ASP.NET Core options.
        options.UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableLogoutEndpointPassthrough()
            .EnableTokenEndpointPassthrough()
            .EnableUserinfoEndpointPassthrough()
            .EnableStatusCodePagesIntegration()
            ;
    })

    // Register the OpenIddict validation components
    .AddValidation(options =>
    {
        // Import the configuration from the local OpenIddict server instance.
        options.UseLocalServer();

        // Register the ASP.NET Core host
        options.UseAspNetCore();
    });

// Register the worker responsible of seeding the database with sample clients.
// Note" in the real world application, this step should be part of setup script.
builder.Services.AddHostedService<ClientDataSeedWorker>();
builder.Services.AddHostedService<UserDataSeedWorker>();

# endregion

builder.Services.AddAuthentication()
    .AddCookie("OpenIddict.Client.AspNetCore");

//builder.Services.AddAuthentication(options =>
//{
//    //options.DefaultAuthenticateScheme = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme;
//    //options.DefaultSignInScheme = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme;
//    //options.DefaultChallengeScheme = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme;
//    //options.DefaultSignOutScheme = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme;

//    options.DefaultScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
//    //options.DefaultAuthenticateScheme = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme;
//});

builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

using (var scope = app.Services.CreateScope())
{
    //add Microsoft.Extensions.DependencyInjection, otherwise it DI can not find the ApplicationDbContext
    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    dbContext.Database.Migrate();
}

   
app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();

app.Run();
