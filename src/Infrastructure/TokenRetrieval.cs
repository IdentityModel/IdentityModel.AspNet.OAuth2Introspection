// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;
using System;

namespace IdentityModel.AspNetCore.OAuth2Introspection
{
    /// <summary>
    /// Defines some common token retrieval strategies
    /// </summary>
    public static class TokenRetrieval
    {
        /// <summary>
        /// Reads the token from the authorization header.
        /// </summary>
        /// <param name="scheme">The scheme (defaults to Bearer).</param>
        public static Func<HttpRequest, string> FromAuthorizationHeader(
            string scheme = OAuth2IntrospectionDefaults.AuthenticationScheme)
        {
            string schemePrefix = scheme + " ";

            return request =>
            {
                if (request.Headers.TryGetValue(HeaderNames.Authorization, out var value) &&
                    value.Count != 0)
                {
                    string authorization = value[0];

                    if (!string.IsNullOrEmpty(authorization) &&
                        authorization.StartsWith(schemePrefix, StringComparison.OrdinalIgnoreCase))
                    {
                        return new string(authorization.AsSpan(schemePrefix.Length).Trim());
                    }
                }

                return null;
            };
        }

        /// <summary>
        /// Reads the token from a query string parameter.
        /// </summary>
        /// <param name="name">The name (defaults to access_token).</param>
        public static Func<HttpRequest, string> FromQueryString(string name = "access_token")
        {
            return request =>
            {
                if (request.Query.TryGetValue(name, out var value) && value.Count > 0)
                    return value[0];

                return null;
            };
        }
    }
}