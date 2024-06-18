
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace TheIdentityServer.Data.Seed
{
    public class ClientDataSeedWorker : IHostedService
    {
        private readonly IServiceProvider serviceProvider;
        private readonly ILogger<ClientDataSeedWorker> logger;

        public ClientDataSeedWorker(IServiceProvider serviceProvider, ILogger<ClientDataSeedWorker> logger)
        {
            this.serviceProvider = serviceProvider;
            this.logger = logger;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            using var scope  = serviceProvider.CreateScope();
            var openIddictManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            #region Postman
            var postmanClientId = "PostmanClient";

            //delete existing one
            var existingPostmanClient = await openIddictManager.FindByClientIdAsync(postmanClientId);
            if (existingPostmanClient != null)
            {
                await openIddictManager.DeleteAsync(existingPostmanClient);
            }

            if (await openIddictManager.FindByClientIdAsync(postmanClientId) == null)
            {
                await openIddictManager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = postmanClientId,
                    ClientSecret = "postman-secret",
                    ConsentType = ConsentTypes.Explicit,
                    DisplayName = "Postman UI App",
                    //RedirectUris = { new Uri("https://oauth.pstmn.io/v1/callback") },
                    RedirectUris = {
                        new Uri("https://oauth.pstmn.io/v1/callback"), //for postman desktop version
                        new Uri("https://oauth.pstmn.io/v1/browser-callback") //for desktop web version
                    },
                    Permissions =
                    {
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.Logout,
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.GrantTypes.RefreshToken,
                        Permissions.GrantTypes.ClientCredentials,
                        Permissions.ResponseTypes.Code,
                        Permissions.Scopes.Email,
                        Permissions.Scopes.Profile,
                        Permissions.Scopes.Roles
                    },
                    Requirements =
                    {
                        Requirements.Features.ProofKeyForCodeExchange
                    }
                });
            }
            #endregion
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }
}
