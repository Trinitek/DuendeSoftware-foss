﻿// Copyright (c) Duende Software. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Duende.AccessTokenManagement;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for IServiceCollection to register the client credentials token management services
/// </summary>
public static class ClientCredentialsTokenManagementServiceCollectionExtensions
{
    /// <summary>
    /// Adds all necessary services for client credentials token management
    /// </summary>
    /// <param name="services"></param>
    /// <param name="options"></param>
    /// <returns></returns>
    public static ClientCredentialsTokenManagementBuilder AddClientCredentialsTokenManagement(
        this IServiceCollection services,
        Action<ClientCredentialsTokenManagementOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        services.Configure(options);
        return services.AddClientCredentialsTokenManagement();
    }

    /// <summary>
    /// Adds all necessary services for client credentials token management
    /// </summary>
    /// <param name="services"></param>
    /// <returns></returns>
    public static ClientCredentialsTokenManagementBuilder AddClientCredentialsTokenManagement(this IServiceCollection services)
    {
        services.TryAddSingleton<ITokenRequestSynchronization, TokenRequestSynchronization>();

        services.TryAddTransient<IClientCredentialsTokenManagementService, ClientCredentialsTokenManagementService>();

        // By default, resolve the distributed cache for the DistributedClientCredentialsTokenCache
        // without key. If desired, a consumers can register the distributed cache with a key
        services.TryAddKeyedTransient<IDistributedCache>(nameof(DistributedClientCredentialsTokenCache), (sp, _) => sp.GetRequiredService<IDistributedCache>());
        services.TryAddTransient<IClientCredentialsTokenCache, DistributedClientCredentialsTokenCache>();
        services.TryAddTransient<IClientCredentialsTokenEndpointService, ClientCredentialsTokenEndpointService>();
        services.TryAddTransient<IClientAssertionService, DefaultClientAssertionService>();

        services.TryAddTransient<IDPoPProofService, DefaultDPoPProofService>();
        services.TryAddTransient<IDPoPKeyStore, DefaultDPoPKeyStore>();

        // ** DistributedDPoPNonceStore **
        // By default, resolve the distributed cache for the DistributedClientCredentialsTokenCache
        // without key. If desired, a consumers can register the distributed cache with a key
        services.TryAddKeyedTransient<IDistributedCache>(nameof(DistributedDPoPNonceStore), (sp, _) => sp.GetRequiredService<IDistributedCache>());
        services.TryAddTransient<IDPoPNonceStore, DistributedDPoPNonceStore>();

        services.AddHttpClient(ClientCredentialsTokenManagementDefaults.BackChannelHttpClientName);

        return new ClientCredentialsTokenManagementBuilder(services);
    }

    /// <summary>
    /// Adds a named HTTP client for the factory that automatically sends a client access token
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/>.</param>
    /// <param name="httpClientName">The name of the client.</param>
    /// <param name="tokenClientName">The name of the token client.</param>
    /// <returns></returns>
    public static IHttpClientBuilder AddClientCredentialsHttpClient(
        this IServiceCollection services,
        string httpClientName,
        string tokenClientName)
    {
        return services.AddClientCredentialsHttpClient(httpClientName, tokenClientName, (Action<HttpClient>)null!);
    }

    /// <summary>
    /// Adds a named HTTP client for the factory that automatically sends a client access token
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/>.</param>
    /// <param name="httpClientName">The name of the client.</param>
    /// <param name="tokenClientName">The name of the token client.</param>
    /// <param name="configureClient">A delegate that is used to configure a <see cref="HttpClient"/>.</param>
    /// <returns></returns>
    public static IHttpClientBuilder AddClientCredentialsHttpClient(
    this IServiceCollection services,
    string httpClientName,
    string tokenClientName,
    Action<HttpClient>? configureClient = null)
    {
        ArgumentNullException.ThrowIfNull(httpClientName);
        ArgumentNullException.ThrowIfNull(tokenClientName);

        if (configureClient != null)
        {
            return services.AddHttpClient(httpClientName, configureClient)
                .AddClientCredentialsTokenHandler(tokenClientName);
        }

        return services.AddHttpClient(httpClientName)
            .AddClientCredentialsTokenHandler(tokenClientName);
    }

    /// <summary>
    /// Adds a named HTTP client for the factory that automatically sends a client access token
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/>.</param>
    /// <param name="httpClientName">The name of the client.</param>
    /// <param name="tokenClientName">The name of the token client.</param>
    /// <param name="configureClient">Additional configuration with service provider instance.</param>
    /// <returns></returns>
    public static IHttpClientBuilder AddClientCredentialsHttpClient(
        this IServiceCollection services,
        string httpClientName,
        string tokenClientName,
        Action<IServiceProvider, HttpClient>? configureClient = null)
    {
        ArgumentNullException.ThrowIfNull(httpClientName);
        ArgumentNullException.ThrowIfNull(tokenClientName);

        if (configureClient != null)
        {
            return services.AddHttpClient(httpClientName, configureClient)
                .AddClientCredentialsTokenHandler(tokenClientName);
        }

        return services.AddHttpClient(httpClientName)
            .AddClientCredentialsTokenHandler(tokenClientName);
    }

    /// <summary>
    /// Adds the client access token handler to an HttpClient
    /// </summary>
    /// <param name="httpClientBuilder"></param>
    /// <param name="tokenClientName"></param>
    /// <returns></returns>
    public static IHttpClientBuilder AddClientCredentialsTokenHandler(
        this IHttpClientBuilder httpClientBuilder,
        string tokenClientName)
    {
        ArgumentNullException.ThrowIfNull(tokenClientName);

        return httpClientBuilder.AddHttpMessageHandler(provider =>
        {
            var dpopService = provider.GetRequiredService<IDPoPProofService>();
            var dpopNonceStore = provider.GetRequiredService<IDPoPNonceStore>();
            var accessTokenManagementService = provider.GetRequiredService<IClientCredentialsTokenManagementService>();
            var logger = provider.GetRequiredService<ILogger<ClientCredentialsTokenHandler>>();

            return new ClientCredentialsTokenHandler(dpopService, dpopNonceStore, accessTokenManagementService, logger, tokenClientName);
        });
    }
}