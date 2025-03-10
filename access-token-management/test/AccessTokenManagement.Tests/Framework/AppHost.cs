// Copyright (c) Duende Software. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using System.Web;
using Duende.IdentityModel;
using Duende.AccessTokenManagement.OpenIdConnect;
using RichardSzalay.MockHttp;
using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;

namespace Duende.AccessTokenManagement.Tests;

public class EagerTokenRefresher(
    IStoreTokensInAuthenticationProperties tokensInProps,
    IOptions<UserTokenManagementOptions> options,
    IUserTokenRequestSynchronization sync,
    IUserTokenEndpointService tokenEndpointService,
    IUserTokenStore userAccessTokenStore,
    TimeProvider clock,
    ILogger<UserAccessAccessTokenManagementService> logger)

{
    public async Task RefreshTokenIfNeeded(ClaimsPrincipal? user, AuthenticationProperties contextProperties,
        CancellationToken cancellationToken)
    {
        var userToken = tokensInProps.GetUserToken(contextProperties);
        var dtRefresh = userToken.Expiration.Subtract(options.Value.RefreshBeforeExpiration);
        var utcNow = clock.GetUtcNow();

        if (userToken.AccessToken == null || userToken.RefreshToken == null)
            return;

        var parameters = new UserTokenRequestParameters();

        if (dtRefresh < utcNow)
        {
            await sync.SynchronizeAsync(userToken.RefreshToken!, async () =>
            {
            try
            {
                var refreshedToken =
            await tokenEndpointService.RefreshAccessTokenAsync(userToken, parameters, cancellationToken).ConfigureAwait(false);
                if (refreshedToken.IsError)
                {
                    logger.LogError("Error refreshing access token. Error = {error}", refreshedToken.Error);
                }
                else
                {
                    tokensInProps.SetUserToken(refreshedToken, contextProperties, parameters);
                }

            }
            catch (Exception ex)
            {

                Console.WriteLine("Exception: " + ex.ToString());
            }
                return null;
            }).ConfigureAwait(false);
        }

    }

}

public class AppHost : GenericHost
{
    public string ClientId;

    private readonly IdentityServerHost _identityServerHost;
    private readonly ApiHost _apiHost;
    private readonly Action<UserTokenManagementOptions>? _configureUserTokenManagementOptions;

    public bool AutoRefreshToken { get; set; } = false;

    public AppHost(
        WriteTestOutput writeTestOutput,
        IdentityServerHost identityServerHost, 
        ApiHost apiHost, 
        string clientId,
        string baseAddress = "https://app",
        Action<UserTokenManagementOptions>? configureUserTokenManagementOptions = default)
        : base(writeTestOutput, baseAddress)
    {
        _identityServerHost = identityServerHost;
        _apiHost = apiHost;
        ClientId = clientId;
        _configureUserTokenManagementOptions = configureUserTokenManagementOptions;
        OnConfigureServices += ConfigureServices;
        OnConfigure += Configure;
    }

    public MockHttpMessageHandler? IdentityServerHttpHandler { get; set; }

    private void ConfigureServices(IServiceCollection services)
    {
        services.AddRouting();
        services.AddAuthorization();
        services.AddTransient<EagerTokenRefresher>();

        services.AddAuthentication("cookie")
            .AddCookie("cookie", options =>
            {
                options.Cookie.Name = "bff";

                options.Events.OnValidatePrincipal += async context =>
                {
                    if (AutoRefreshToken)
                    {
                        var refresher = context.HttpContext.RequestServices.GetRequiredService<EagerTokenRefresher>();

                        await refresher.RefreshTokenIfNeeded(context.Principal, context.Properties, context.HttpContext.RequestAborted);
                    }
                };
            });

        services.AddAuthentication(options =>
            {
                options.DefaultChallengeScheme = "oidc";
                options.DefaultSignOutScheme = "oidc";
            })
            .AddOpenIdConnect("oidc", options =>
            {
                options.Events.OnRedirectToIdentityProviderForSignOut = async e =>
                {
                    await e.HttpContext.RevokeRefreshTokenAsync();
                };
                
                options.Authority = _identityServerHost.Url();

                options.ClientId = ClientId;
                options.ClientSecret = "secret";
                options.ResponseType = "code";
                options.ResponseMode = "query";

                options.MapInboundClaims = false;
                options.GetClaimsFromUserInfoEndpoint = false;
                options.SaveTokens = true;

                options.Scope.Clear();
                var client = _identityServerHost.Clients.Single(x => x.ClientId == ClientId);
                foreach (var scope in client.AllowedScopes)
                {
                    options.Scope.Add(scope);
                }

                if (client.AllowOfflineAccess)
                {
                    options.Scope.Add("offline_access");
                }

                var identityServerHandler = _identityServerHost.Server.CreateHandler();   
                if (IdentityServerHttpHandler != null)
                {
                    // allow discovery document
                    IdentityServerHttpHandler.When("/.well-known/*")
                        .Respond(identityServerHandler);
                    
                    options.BackchannelHttpHandler = new LoggingHttpHandler(IdentityServerHttpHandler);
                }
                else
                {
                    options.BackchannelHttpHandler = new LoggingHttpHandler(identityServerHandler);
                }

                options.ProtocolValidator.RequireNonce = false;
            });

        services.AddDistributedMemoryCache();
        services.AddOpenIdConnectAccessTokenManagement(opt =>
        {
            opt.UseChallengeSchemeScopedTokens = true;

            if (_configureUserTokenManagementOptions != null)
            {
                _configureUserTokenManagementOptions(opt);
            }
        });

        services.AddUserAccessTokenHttpClient("callApi", configureClient: client => {
            client.BaseAddress = new Uri(_apiHost.Url());
        })
        .ConfigurePrimaryHttpMessageHandler(() => new LoggingHttpHandler(_apiHost.HttpMessageHandler));
    }

    private void Configure(IApplicationBuilder app)
    {
        app.UseAuthentication();
        app.UseRouting();
        app.UseAuthorization();

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapGet("/login", async context =>
            {
                await context.ChallengeAsync(new AuthenticationProperties
                {
                    RedirectUri = "/"
                });
            });
                
            endpoints.MapGet("/logout", async context =>
            {
                await context.SignOutAsync();
            });
            
            endpoints.MapGet("/user_token", async context =>
            {
                var token = await context.GetUserAccessTokenAsync();
                await context.Response.WriteAsJsonAsync(token);
            });

            endpoints.MapGet("/call_api", async (IHttpClientFactory factory, HttpContext context) =>
            {
                var http = factory.CreateClient("callApi");
                var response = await http.GetAsync("test");
                return await response.Content.ReadFromJsonAsync<TokenEchoResponse>();
            });

            endpoints.MapGet("/user_token_with_resource/{resource}", async (string resource, HttpContext context) =>
            {
                var token = await context.GetUserAccessTokenAsync(new UserTokenRequestParameters
                {
                    Resource = resource
                });
                await context.Response.WriteAsJsonAsync(token);
            });
            
            endpoints.MapGet("/client_token", async context =>
            {
                var token = await context.GetClientAccessTokenAsync();
                await context.Response.WriteAsJsonAsync(token);
            });
        });
    }

    public async Task<HttpResponseMessage> LoginAsync(string sub, string? sid = null, bool verifyDpopThumbprintSent = false)
    {
        await _identityServerHost.CreateIdentityServerSessionCookieAsync(sub, sid);
        return await OidcLoginAsync(verifyDpopThumbprintSent);
    }

    public async Task<HttpResponseMessage> OidcLoginAsync(bool verifyDpopThumbprintSent)
    {
        var response = await BrowserClient.GetAsync(Url("/login"));
        response.StatusCode.ShouldBe((HttpStatusCode)302); // authorize
        response.Headers.Location!.ToString().ToLowerInvariant().ShouldStartWith(_identityServerHost.Url("/connect/authorize"));

        if (verifyDpopThumbprintSent)
        {
            var queryParams = HttpUtility.ParseQueryString(response.Headers.Location.Query);
            queryParams.AllKeys.ShouldContain(OidcConstants.AuthorizeRequest.DPoPKeyThumbprint);
        }

        response = await _identityServerHost.BrowserClient.GetAsync(response.Headers.Location.ToString());
        response.StatusCode.ShouldBe((HttpStatusCode)302); // client callback
        response.Headers.Location!.ToString().ToLowerInvariant().ShouldStartWith(Url("/signin-oidc"));

        response = await BrowserClient.GetAsync(response.Headers.Location.ToString());
        response.StatusCode.ShouldBe((HttpStatusCode)302); // root
        response.Headers.Location!.ToString().ToLowerInvariant().ShouldBe("/");

        response = await BrowserClient.GetAsync(Url(response.Headers.Location.ToString()));
        return response;
    }

    public async Task<HttpResponseMessage> LogoutAsync(string? sid = null)
    {
        var response = await BrowserClient.GetAsync(Url("/logout") + "?sid=" + sid);
        response.StatusCode.ShouldBe((HttpStatusCode)302); // endsession
        response.Headers.Location!.ToString().ToLowerInvariant().ShouldStartWith(_identityServerHost.Url("/connect/endsession"));

        response = await _identityServerHost.BrowserClient.GetAsync(response.Headers.Location.ToString());
        response.StatusCode.ShouldBe((HttpStatusCode)302); // logout
        response.Headers.Location!.ToString().ToLowerInvariant().ShouldStartWith(_identityServerHost.Url("/account/logout"));

        response = await _identityServerHost.BrowserClient.GetAsync(response.Headers.Location.ToString());
        response.StatusCode.ShouldBe((HttpStatusCode)302); // post logout redirect uri
        response.Headers.Location!.ToString().ToLowerInvariant().ShouldStartWith(Url("/signout-callback-oidc"));

        response = await BrowserClient.GetAsync(response.Headers.Location.ToString());
        response.StatusCode.ShouldBe((HttpStatusCode)302); // root

        response = await BrowserClient.GetAsync(Url(response.Headers.Location!.ToString()));
        return response;
    }
}

public class LoggingHttpHandler(HttpMessageHandler inner) : DelegatingHandler(inner)
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        try
        {
            Console.WriteLine("--> " + request.RequestUri!.ToString());

            var response = await base.SendAsync(request, cancellationToken);

            Console.WriteLine("<-- " + response.RequestMessage!.RequestUri!.ToString() + " - " + response.StatusCode);
            return response;
        }
        catch (Exception ex)
        {
            Console.WriteLine("Exception: " + ex.ToString());
            throw;
        }
    }
}