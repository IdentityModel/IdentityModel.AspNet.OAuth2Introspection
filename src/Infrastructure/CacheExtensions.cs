// Copyright (c) Duende Software. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace IdentityModel.AspNetCore.OAuth2Introspection
{
    internal static class CacheExtensions
    {
        private static readonly JsonSerializerOptions Options;

        static CacheExtensions()
        {    
            Options = new JsonSerializerOptions
            {
                IgnoreReadOnlyFields = true,
                IgnoreReadOnlyProperties = true,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
            };
   
            Options.Converters.Add(new ClaimConverter());
        }

        public static async Task<IEnumerable<Claim>> GetClaimsAsync(this IDistributedCache cache, OAuth2IntrospectionOptions options, string token)
        {
            var cacheKey = options.CacheKeyGenerator(options,token);
            var bytes = await cache.GetAsync(cacheKey).ConfigureAwait(false);

            if (bytes == null)
            {
                return null;
            }

            var json = Encoding.UTF8.GetString(bytes);
            return JsonSerializer.Deserialize<IEnumerable<Claim>>(json, Options);
        }

        public static async Task SetClaimsAsync(this IDistributedCache cache, OAuth2IntrospectionOptions options, string token, IEnumerable<Claim> claims, TimeSpan duration, ILogger logger)
        {
            var expClaim = claims.FirstOrDefault(c => c.Type == JwtClaimTypes.Expiration);

            var now = DateTimeOffset.UtcNow;
            var expiration = expClaim == null
                ? now + duration
                : DateTimeOffset.FromUnixTimeSeconds(long.Parse(expClaim.Value));
            logger.LogDebug("Token will expire in {expiration}", expiration);

            if (expiration <= now)
            {
                return;
            }

            // if the lifetime of the token is shorter than the duration, use the remaining token lifetime
            DateTimeOffset absoluteLifetime;
            if (expiration <= now.Add(duration))
            {
                absoluteLifetime = expiration;
            }
            else
            {
                absoluteLifetime = now.Add(duration);
            }

            var json = JsonSerializer.Serialize(claims, Options);
            var bytes = Encoding.UTF8.GetBytes(json);

            logger.LogDebug("Setting cache item expiration to {expiration}", absoluteLifetime);
            var cacheKey = options.CacheKeyGenerator(options, token);
            await cache.SetAsync(cacheKey, bytes, new DistributedCacheEntryOptions { AbsoluteExpiration = absoluteLifetime }).ConfigureAwait(false);
        }
    }
}