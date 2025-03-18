// Copyright (c) Duende Software. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.Extensions.Caching.Hybrid;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Duende.AccessTokenManagement;

public static class ServiceProviderKeys
{
    public const string DistributedClientCredentialsTokenCache = "DistributedClientCredentialsTokenCache";
    public const string DistributedDPoPNonceStore = "DistributedDPoPNonceStore";
}

/// <summary>
/// Client access token cache using IDistributedCache
/// </summary>
public class DistributedClientCredentialsTokenCache(
    [FromKeyedServices(ServiceProviderKeys.DistributedClientCredentialsTokenCache)]HybridCache cache,
    TimeProvider time,
    IOptions<ClientCredentialsTokenManagementOptions> options,
    ILogger<DistributedClientCredentialsTokenCache> logger
    )
    : IClientCredentialsTokenCache
{
    private readonly ClientCredentialsTokenManagementOptions _options = options.Value;

    /// <inheritdoc/>
    public async Task SetAsync(
        string clientName,
        ClientCredentialsToken clientCredentialsToken,
        TokenRequestParameters requestParameters,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(clientName);

        try
        {
            var entryOptions = GetHybridCacheEntryOptions(clientName, clientCredentialsToken);

            var cacheKey = GenerateCacheKey(_options, clientName, requestParameters);
            await cache.SetAsync(cacheKey, clientCredentialsToken, entryOptions, cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (Exception e)
        {
            logger.LogError(e,
                "Error trying to set token in cache for client {clientName}. Error = {error}",
                clientName, e.Message);
        }
    }

    private HybridCacheEntryOptions GetHybridCacheEntryOptions(string clientName,
        ClientCredentialsToken clientCredentialsToken)
    {
        var absoluteCacheExpiration = clientCredentialsToken.Expiration.AddSeconds(-_options.CacheLifetimeBuffer);
        var relativeCacheExpiration = absoluteCacheExpiration - time.GetUtcNow();
        var entryOptions = new HybridCacheEntryOptions()
        {
            Expiration = relativeCacheExpiration
        };

        logger.LogTrace("Caching access token for client: {clientName}. Expiration: {expiration}", clientName, absoluteCacheExpiration);
        return entryOptions;
    }

    private class TokenErrorException(ClientCredentialsToken token) : Exception
    {
        public ClientCredentialsToken Token { get; } = token;
    }
    public async Task<ClientCredentialsToken> GetOrCreateAsync(
        string clientName, TokenRequestParameters requestParameters,
        Func<string, TokenRequestParameters, CancellationToken, Task<ClientCredentialsToken>> factory,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(clientName);

        var cacheKey = GenerateCacheKey(_options, clientName, requestParameters);

        ClientCredentialsToken token;
        if (!requestParameters.ForceRenewal)
        {
            try
            {
                // We don't need the token to be absolutely fresh, so we can get one from the cache. 
                // The GetOrCreate pattern unfortunately doesn't allow us to create a cache entry
                // that's only valid for as long as it needs to be. 
                token = await cache.GetOrCreateAsync(
                    key: cacheKey,
                    factory: async (ct) =>
                    {
                        var result = await factory(clientName, requestParameters, ct).ConfigureAwait(false);
                        if (result.IsError)
                        {
                            // If the token is an error, we throw an exception to prevent the value from being cached
                            throw new TokenErrorException(result);
                        }

                        return result;
                    },
                    cancellationToken: cancellationToken);
            }
            catch (TokenErrorException ex)
            {
                return ex.Token;
            }

            if (token.Expiration != DateTimeOffset.MinValue)
            {
                var absoluteCacheExpiration = token.Expiration.AddSeconds(-_options.CacheLifetimeBuffer);

                if (absoluteCacheExpiration > time.GetUtcNow())
                {
                    return token;
                }
            }
        }
        token = await factory(clientName, requestParameters, cancellationToken).ConfigureAwait(false);

        if (!token.IsError)
        {
            await SetAsync(clientName, token, requestParameters, cancellationToken);
        }

        return token;
    }


    /// <inheritdoc/>
    public ValueTask DeleteAsync(
        string clientName,
        TokenRequestParameters requestParameters,
        CancellationToken cancellationToken = default)
    {
        if (clientName is null) throw new ArgumentNullException(nameof(clientName));

        var cacheKey = GenerateCacheKey(_options, clientName, requestParameters);
        return cache.RemoveAsync(cacheKey, cancellationToken);
    }

    /// <summary>
    /// Generates the cache key based on various inputs
    /// </summary>
    /// <param name="options"></param>
    /// <param name="clientName"></param>
    /// <param name="parameters"></param>
    /// <returns></returns>
    protected virtual string GenerateCacheKey(
        ClientCredentialsTokenManagementOptions options, 
        string clientName,
        TokenRequestParameters? parameters = null)
    {
        var s = "s_" + parameters?.Scope ?? "";
        var r = "r_" + parameters?.Resource ?? "";

        return options.CacheKeyPrefix + clientName + "::" + s + "::" + r;
    }
}