using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Client.AspNetCore;
using OpenIddict.Server.AspNetCore;
using System.Collections.Immutable;
using System.Security.Claims;
using System.Security.Cryptography.Xml;
using TheIdentityServer.Attributes;
using TheIdentityServer.Extensions;
using TheIdentityServer.ViewModels;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace TheIdentityServer.Controllers.Web.OpenId
{
    public class AuthorizationController : BaseWebController<AuthorizationController>
    {
        private readonly IOpenIddictApplicationManager applicationManager;
        private readonly IOpenIddictAuthorizationManager authorizationManager;
        private readonly IOpenIddictScopeManager scopeManager;
        private readonly SignInManager<IdentityUser> signInManager;
        private readonly UserManager<IdentityUser> userManager;

        public AuthorizationController(
            IOpenIddictApplicationManager applicationManager,
            IOpenIddictAuthorizationManager authorizationManager,
            IOpenIddictScopeManager scopeManager,
            SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager)
        {
            this.applicationManager = applicationManager;
            this.authorizationManager = authorizationManager;
            this.scopeManager = scopeManager;
            this.signInManager = signInManager;
            this.userManager = userManager;
        }

        [HttpGet("~/connect/authorize")]
        [HttpPost("~/connect/authorize")]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> Authorize()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved");
            /*
            Try to retrieve the user principal stored in the authentication cookie and redirect
            the user agent to the login page (or to an external provider) in the following cases:
            
            - If the user principal can not be extracted pr the cookie is too old.
            - If prompt=login was specified by the client application
            - If a max_age parameter was provided and the authentication cookie is not considered "fresh" enough
            */

            var result = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
            if (result == null ||
                !result.Succeeded ||
                request.HasPrompt(Prompts.Login) ||
                request.MaxAge != null && result.Properties?.IssuedUtc != null && DateTimeOffset.UtcNow - result.Properties.IssuedUtc > TimeSpan.FromSeconds(request.MaxAge.Value)
            )
            {
                // If the client application requested promptless authentication,
                // return an error indicating that the user is not logged in.
                if (request.HasPrompt(Prompts.None))
                {
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.LoginRequired,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is not logged in"
                        })
                    );
                }

                /*
                To avoid endless login -> authorization redirects, 
                the prompt=login flag is removed from the authorization request payload before redirecting to the user.
                */

                var prompt = string.Join(" ", request.GetPrompts().Remove(Prompts.Login));

                var parameters = Request.HasFormContentType ?
                    Request.Form.Where(param => param.Key != Parameters.Prompt).ToList() :
                    Request.Query.Where(param => param.Key != Parameters.Prompt).ToList();

                parameters.Add(KeyValuePair.Create(Parameters.Prompt, new StringValues(prompt)));

                return Challenge(
                    authenticationSchemes: IdentityConstants.ApplicationScheme,
                    properties: new AuthenticationProperties
                    {
                        RedirectUri = Request.PathBase + Request.Path + QueryString.Create(parameters)
                    });
            }

            // Retrieve the profile of the logged in user
            var user = await userManager.GetUserAsync(result.Principal) ?? throw new InvalidOperationException("The user detail not found");

            // Retrieve the application from database
            var application = await applicationManager.FindByClientIdAsync(request.ClientId ?? string.Empty) ?? throw new InvalidOperationException("The calling client not registred");

            // Retrieve the permanent authorizations associated with the user and the calling client application
            var authorizations = await authorizationManager.FindAsync(
                subject: await userManager.GetUserIdAsync(user),
                client: await applicationManager.GetIdAsync(application) ?? string.Empty,
                status: Statuses.Valid,
                type: AuthorizationTypes.Permanent,
                scopes: request.GetScopes()
                ).ToListAsync();


            switch (await applicationManager.GetConsentTypeAsync(application))
            {
                // If consent is external (e.g when authorizations are granted by a sysadmin)
                // immediately return an error if no authorization can be found in the database
                case ConsentTypes.External when !authorizations.Any():
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The logged in user is not allowed to access the client application"
                        })
                    );

                // If the consent is implicit or if an authorization was found
                // return an authorization response without displaying the consent form.
                case ConsentTypes.Implicit:
                case ConsentTypes.External when authorizations.Any():
                case ConsentTypes.Explicit when authorizations.Any() && !request.HasPrompt(Prompts.Consent):

                    // Create the claims-based identity that will be used by the OpenIddic to generate tokens
                    var identity = new ClaimsIdentity(
                        authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                        nameType: Claims.Name,
                        roleType: Claims.Role
                    );


                    // Add the claims that will be persisted in the tokens
                    identity.SetClaim(Claims.Subject, await userManager.GetUserIdAsync(user))
                            .SetClaim(Claims.Email, await userManager.GetEmailAsync(user))
                            .SetClaim(Claims.Name, await userManager.GetUserNameAsync(user))
                            .SetClaims(Claims.Role, (await userManager.GetRolesAsync(user)).ToImmutableArray());


                    // Note: in this sample, the granted scopes match the requested scope
                    // but you may want to allow the user to uncheck specific scopes.
                    // For that, simply restrict the list of scopes before calling SetScopes.
                    identity.SetScopes(request.GetScopes());
                    identity.SetResources(await scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());

                    // Automatically create a permanent authorization to avoid requiring explicit consent
                    // for future authorization or token requests containing the same scopes.
                    var authorization = authorizations.LastOrDefault();
                    authorization ??= await authorizationManager.CreateAsync(
                            identity: identity,
                            subject: await userManager.GetUserIdAsync(user),
                            client: await applicationManager.GetIdAsync(application) ?? string.Empty,
                            type: AuthorizationTypes.Permanent,
                            scopes: identity.GetScopes()
                        );

                    identity.SetAuthorizationId(await authorizationManager.GetIdAsync(authorization));
                    identity.SetDestinations(GetDestinations);

                    return SignIn(new ClaimsPrincipal(identity), OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);

                // At this point, no authorization was found in the database and an error must be returned
                // if the client application specified prompt=none in the authorization request.
                case ConsentTypes.Explicit when request.HasPrompt(Prompts.None):
                case ConsentTypes.Systematic when request.HasPrompt(Prompts.None):
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Interactive user consent is required"
                        })
                    );

                // in every other case, render the consent form
                default:
                    return View(new AuthorizeViewModel
                    {
                        ApplicationName = await applicationManager.GetLocalizedDisplayNameAsync(application),
                        Scope = request.Scope
                    });
            }
        }



        [Authorize, FormValueRequired("submit.Accept")]
        [HttpPost("~/connect/authorize"), ValidateAntiForgeryToken]
        public async Task<IActionResult> Accept()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                throw new InvalidOperationException("The OpenID Connect request can not be retrieved");

            // Retrieve the profile of the logged in user
            var user = await userManager.GetUserAsync(User) ??
                throw new InvalidOperationException("The user is not found");

            // Retrieve the application details from DB
            var application = await applicationManager.FindByClientIdAsync(request.ClientId ?? string.Empty) ??
                throw new InvalidOperationException("The calling client can not be found");

            // Retrieve the permanent authorization associated with the user and the calling client application
            var authorizations = await authorizationManager.FindAsync(
                    subject: await userManager.GetUserIdAsync(user),
                    client: await applicationManager.GetIdAsync(application) ?? string.Empty,
                    status: Statuses.Valid,
                    type: AuthorizationTypes.Permanent,
                    scopes: request.GetScopes()
            ).ToListAsync();

            // Note: the same check is already made in the other action but is repeated.
            // Here is to ensure a malicious user can't abuse this POST-only endpoint and
            // force it to return a valid responsee without the external authorization.
            if (!authorizations.Any() && await applicationManager.HasConsentTypeAsync(application, ConsentTypes.External))
            {
                return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The logged in user is not allowed to access this client applications"
                        })
                );
            }

            // Create the claims-based identity that will be used by the OpenIddic to generate tokens
            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role
            );


            // Add the claims that will be persisted in the tokens
            identity.SetClaim(Claims.Subject, await userManager.GetUserIdAsync(user))
                    .SetClaim(Claims.Email, await userManager.GetEmailAsync(user))
                    .SetClaim(Claims.Name, await userManager.GetUserNameAsync(user))
                    .SetClaims(Claims.Role, (await userManager.GetRolesAsync(user)).ToImmutableArray());

            // Note: in this sample, the granted scopes match the requested scope
            // but you may want to allow the user to uncheck specific scopes.
            // For that, simply restrict the list of scopes before calling SetScopes.
            identity.SetScopes(request.GetScopes());
            identity.SetResources(await scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());

            // Automatically create a permanent authorization to avoid requiring explicit consent
            // for future authorization or token requests containing the same scopes.
            var authorization = authorizations.LastOrDefault();
            authorization ??= await authorizationManager.CreateAsync(
                    identity: identity,
                    subject: await userManager.GetUserIdAsync(user),
                    client: await applicationManager.GetIdAsync(application) ?? string.Empty,
                    type: AuthorizationTypes.Permanent,
                    scopes: identity.GetScopes()
                );

            identity.SetAuthorizationId(await authorizationManager.GetIdAsync(authorization));
            identity.SetDestinations(GetDestinations);

            return SignIn(new ClaimsPrincipal(identity), OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
        }

        [Authorize, FormValueRequired("submit.Deny")]
        [HttpPost("~/connect/authorize"), ValidateAntiForgeryToken]
        public IActionResult Deny()
        {
            return Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        [HttpGet("~/connect/logout")]
        public IActionResult Logout()
        {
            return View();
        }


        [ActionName(nameof(Logout)), HttpPost("~/connect/logout"), ValidateAntiForgeryToken]
        public async Task<IActionResult> LogoutPost()
        {
            // Ask ASP.NET Core Identity to delete the local and external cookies created
            // when the user agent is redirected from the external identity provider
            // after a successful authentication flow (e.g Google or Facebook).
            await signInManager.SignOutAsync();

            // Returning a SignOutResult will ask OpenIddict to redirect the user agent
            // to the post_logout_redirect_uri specified by the client application or to
            // the RedirectUri specified in the authentication properties if none was set.
            return SignOut(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = "/"
                });
        }

        [HttpPost("~/connect/token"), IgnoreAntiforgeryToken, Produces("application/json")]
        public async Task<IActionResult> Exchange()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                throw new InvalidOperationException("The OpenID connect request can not be retrieved");

            if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
            {
                // Retrieve claim principal stored in the authorization code/refresh token
                var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

                // Retrieve the user profile corresponding to the authorization code/refresh token.
                var user = await userManager.FindByIdAsync(result.Principal?.GetClaim(Claims.Subject) ?? string.Empty);
                if (user is null)
                {
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The token is no longer valid"
                        })
                    );
                }

                // Ensure the user is still allowed to sign in
                if (!await signInManager.CanSignInAsync(user))
                {
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is no longer allowed to sign in"
                        })
                    );
                }


                var identity = new ClaimsIdentity(result.Principal?.Claims,
                    authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                    nameType: Claims.Name,
                    roleType: Claims.Role
                );


                // Override the user claims present in the principal in case the changed since the authorization code/refresh token was issued.
                identity.SetClaim(Claims.Subject, await userManager.GetUserIdAsync(user))
                        .SetClaim(Claims.Email, await userManager.GetEmailAsync(user))
                        .SetClaim(Claims.Name, await userManager.GetUserNameAsync(user))
                        .SetClaims(Claims.Role, (await userManager.GetRolesAsync(user)).ToImmutableArray());

                identity.SetDestinations(GetDestinations);

                // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens
                return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            throw new InvalidOperationException("The specified grant type is not supported");
        }

        private static IEnumerable<string> GetDestinations(Claim claim)
        {
            // By default, claims are NOT authomatically included in the access and identity tokens.
            // To allow OpenIddict to serialize them, you must attach them a destination
            // that specifies whether they should be included in access token, identity token or both

            if (claim.Subject is not null)
            {
                switch (claim.Type)
                {
                    case Claims.Name:
                        yield return Destinations.AccessToken;

                        if (claim.Subject.HasScope(Scopes.Profile))
                            yield return Destinations.IdentityToken;

                        yield break;

                    case Claims.Email:
                        yield return Destinations.AccessToken;

                        if (claim.Subject.HasScope(Scopes.Email))
                            yield return Destinations.IdentityToken;

                        yield break;

                    case Claims.Role:
                        yield return Destinations.AccessToken;

                        if (claim.Subject.HasScope(Scopes.Roles))
                            yield return Destinations.IdentityToken;

                        yield break;

                    case "AspNet.Identity.SecurityStamp":
                        yield break;

                    default:
                        yield return Destinations.AccessToken;
                        yield break;
                }
            }
        }
    }
}
