// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Text;

namespace IdentityModel.AspNetCore.OAuth2Introspection.Infrastructure
{
    /// <summary>
    /// Defines some common cache utilities
    /// </summary>
    public static class CacheUtils
    {
        /// <summary>
        /// Generates a cache key based opon input from OAuth2IntrospectionOptions and the token.
        /// </summary>
        /// <returns></returns>
        public static Func<OAuth2IntrospectionOptions,string, string> CacheKeyFromToken()
        {
            return (options, token) => token.Sha256(options.CacheKeyPrefix);
        }
    }
}
