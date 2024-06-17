using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;

namespace SSO.TheOpenIddict;

public class TestDataHostedService: IHostedService
{
    private readonly IServiceProvider _serviceProvider;

    public TestDataHostedService(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using var scope = _serviceProvider.CreateScope();

        var context = scope.ServiceProvider.GetRequiredService<DbContext>();
        await context.Database.EnsureCreatedAsync(cancellationToken);

        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        if (await manager.FindByClientIdAsync("postman", cancellationToken) is null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "postman",
                ClientSecret = "postman-secret",
                DisplayName = "Postman",
                // Permissions =
                // {
                //     OpenIddictConstants.Permissions.Endpoints.Token,
                //     OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,

                //     OpenIddictConstants.Permissions.Prefixes.Scope + "api"
                // },


                RedirectUris = 
                { 
                    new Uri("https://oauth.pstmn.io/v1/callback"), //for postman desktop version
                    new Uri("https://oauth.pstmn.io/v1/browser-callback") //for desktop web version
                },
                Permissions =
                {

                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.Token,

                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,

                    OpenIddictConstants.Permissions.Prefixes.Scope + "api",

                    OpenIddictConstants.Permissions.ResponseTypes.Code
                }
            }, cancellationToken);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}