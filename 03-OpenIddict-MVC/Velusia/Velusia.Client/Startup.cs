using System;
using System.IO;
using System.Net.Http;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Client;
using OpenIddict.Validation.SystemNetHttp;
using Quartz;
using Velusia.Client.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Velusia.Client;

public class Startup
{
    public Startup(IConfiguration configuration)
        => Configuration = configuration;

    public IConfiguration Configuration { get; }

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddDbContext<ApplicationDbContext>(options =>
        {
            // Configure the context to use sqlite.
            //options.UseSqlite($"Filename={Path.Combine(Path.GetTempPath(), "openiddict-velusia-client.sqlite3")}");
            options.UseInMemoryDatabase(nameof(ApplicationDbContext));
            
            // Register the entity sets needed by OpenIddict.
            // Note: use the generic overload if you need
            // to replace the default OpenIddict entities.
            options.UseOpenIddict();
        });

        services.AddAuthentication(options =>
        {
            options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        })

        .AddCookie(options =>
        {
            options.LoginPath = "/login";
            options.LogoutPath = "/logout";
            options.ExpireTimeSpan = TimeSpan.FromMinutes(50);
            options.SlidingExpiration = false;
        });

        // OpenIddict offers native integration with Quartz.NET to perform scheduled tasks
        // (like pruning orphaned authorizations from the database) at regular intervals.
        services.AddQuartz(options =>
        {
            //options.UseMicrosoftDependencyInjectionJobFactory();
            options.UseSimpleTypeLoader();
            options.UseInMemoryStore();
        });

        // Register the Quartz.NET service and configure it to block shutdown until jobs are complete.
        services.AddQuartzHostedService(options => options.WaitForJobsToComplete = true);

        services.AddOpenIddict()

            // Register the OpenIddict core components.
            .AddCore(options =>
            {
                // Configure OpenIddict to use the Entity Framework Core stores and models.
                // Note: call ReplaceDefaultEntities() to replace the default OpenIddict entities.
                options.UseEntityFrameworkCore()
                       .UseDbContext<ApplicationDbContext>();

                // Developers who prefer using MongoDB can remove the previous lines
                // and configure OpenIddict to use the specified MongoDB database:
                // options.UseMongoDb()
                //        .UseDatabase(new MongoClient().GetDatabase("openiddict"));

                // Enable Quartz.NET integration.
                //options.UseQuartz();
            })

            // Register the OpenIddict client components.
            .AddClient(options =>
            {
                // Note: this sample uses the code flow, but you can enable the other flows if necessary.
                options.AllowAuthorizationCodeFlow();

                // Register the signing and encryption credentials used to protect
                // sensitive data like the state tokens produced by OpenIddict.
                options.AddDevelopmentEncryptionCertificate()
                       .AddDevelopmentSigningCertificate();

                // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
                options.UseAspNetCore()
                       .EnableStatusCodePagesIntegration()
                       .EnableRedirectionEndpointPassthrough()
                       .EnablePostLogoutRedirectionEndpointPassthrough();

                // Register the System.Net.Http integration and use the identity of the current
                // assembly as a more specific user agent, which can be useful when dealing with
                // providers that use the user agent as a way to throttle requests (e.g Reddit).
                options.UseSystemNetHttp()
                       .SetProductInformation(typeof(Startup).Assembly);

                // Add a client registration matching the client application definition in the server project.
                options.AddRegistration(new OpenIddictClientRegistration
                {
                    Issuer = new Uri("https://localhost:44313/", UriKind.Absolute),

                    ClientId = "mvc",
                    ClientSecret = "901564A5-E7FE-42CB-B10D-61EF6A8F3654",
                    Scopes = { Scopes.Email, Scopes.Profile },

                    // Note: to mitigate mix-up attacks, it's recommended to use a unique redirection endpoint
                    // URI per provider, unless all the registered providers support returning a special "iss"
                    // parameter containing their URL as part of authorization responses. For more information,
                    // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.4.
                    RedirectUri = new Uri("callback/login/local", UriKind.Relative),
                    PostLogoutRedirectUri = new Uri("callback/logout/local", UriKind.Relative)
                });

                options.UseSystemNetHttp()
                    .ConfigureHttpClientHandler(handler =>
                    {
                        handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
                    });
            })
            .AddValidation(options =>
            {
                options.UseSystemNetHttp()
                    .ConfigureHttpClientHandler(handler =>
                    {
                        handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
                    });
            })
            ;

        //services.AddHttpClient();

        services.AddHttpClient(typeof(OpenIddictValidationSystemNetHttpOptions).Assembly.GetName().Name)
            .ConfigurePrimaryHttpMessageHandler(_ => new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            });

        // services.AddHttpClient("uri-group") //default healthcheck registration name for uri ( you can change it on AddUrlGroup )
        //         .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler()
        //         {
        //             ClientCertificateOptions = ClientCertificateOption.Manual,
        //             ServerCertificateCustomValidationCallback = (httpRequestMessage, cert, cetChain, policyErrors) =>
        //             {
        //                 return true;
        //             }
        //         });

        services.AddControllersWithViews();

        // Register the worker responsible for creating the database used to store tokens.
        // Note: in a real world application, this step should be part of a setup script.
        services.AddHostedService<Worker>();
    }

    public void Configure(IApplicationBuilder app)
    {
        app.UseDeveloperExceptionPage();

        app.UseStaticFiles();

        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllers();
            endpoints.MapDefaultControllerRoute();
        });
    }
}
