// Copyright (c) Duende Software. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Duende.IdentityServer.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Duende.IdentityModel.OidcClient.DPoP.Framework;

public class IdentityServerHost : GenericHost
{
    public IdentityServerHost(string baseAddress = "https://identityserver")
        : base(baseAddress)
    {
        OnConfigureServices += ConfigureServices;
        OnConfigure += Configure;
    }

    public List<IdentityServer.Models.Client> Clients { get; set; } = new();
    public List<IdentityResource> IdentityResources { get; set; } =
    [
        new IdentityResources.OpenId(),
        new IdentityResources.Profile(),
        new IdentityResources.Email()
    ];

    public List<ApiScope> ApiScopes { get; set; } = new();

    private void ConfigureServices(IServiceCollection services)
    {
        services.AddRouting();
        services.AddAuthorization();

        services.AddLogging(logging =>
        {
            logging.AddFilter("Duende", LogLevel.Debug);
        });

        services.AddIdentityServer(options =>
            {
                options.EmitStaticAudienceClaim = true;
            })
            .AddInMemoryClients(Clients)
            .AddInMemoryIdentityResources(IdentityResources)
            .AddInMemoryApiScopes(ApiScopes);
    }

    private void Configure(IApplicationBuilder app) => app.UseIdentityServer();
}
