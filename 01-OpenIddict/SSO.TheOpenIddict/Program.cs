using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using SSO.TheOpenIddict;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
        {
            options.LoginPath = "/account/login";
        });


builder.Services.AddDbContext<DbContext>(options =>
{
    // Configure the context to use an in-memory store.
    options.UseInMemoryDatabase(nameof(DbContext));
    // Register the entity sets needed by OpenIddict.
    options.UseOpenIddict();
});

builder.Services.AddOpenIddict()
    // Register the OpenIddict core components.
    .AddCore(options =>
    {
        // Configure OpenIddict to use the EF Core stores/models.
        options.UseEntityFrameworkCore()
            .UseDbContext<DbContext>();
    })
    // Register the OpenIddict server components.
    .AddServer(options =>
    {
        //AuthorizationCodeFlow
        options.AllowAuthorizationCodeFlow()
                .RequireProofKeyForCodeExchange()
                .AllowClientCredentialsFlow()
                .AllowRefreshTokenFlow();
                ;

        options.SetAuthorizationEndpointUris("/connect/authorize")
                .SetTokenEndpointUris("/connect/token")
                .SetUserinfoEndpointUris("/connect/userinfo")
                ;

        //ClientCredentialsFlow
        options.AllowClientCredentialsFlow();
        options.SetTokenEndpointUris("/connect/token");

        

        // Encryption and signing of tokens
        options
            .AddEphemeralEncryptionKey()
            .AddEphemeralSigningKey()
            .DisableAccessTokenEncryption() //jika akan disable ecrypt payload
            ;

        // Register scopes (permissions)
        options.RegisterScopes("api")
                .RegisterScopes("offline_access")
            ;

        // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
        options
            .UseAspNetCore()
            .EnableTokenEndpointPassthrough()
            .EnableAuthorizationEndpointPassthrough()
            ;     
    });

builder.Services.AddHostedService<TestDataHostedService>();

var app = builder.Build();



//app.MapGet("/", () => "Hello World!");


app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

// app.UseEndpoints(endpoints =>
//             {
//                 endpoints.MapDefaultControllerRoute();
//            });
app.Run();
