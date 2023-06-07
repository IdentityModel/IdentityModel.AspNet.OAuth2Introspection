﻿// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System.Text.Json;

namespace IdentityModel.AspNetCore.OAuth2Introspection
{
    /// <summary>
    /// Context for the ParseExtraClaims event
    /// </summary>
    public class ParseExtraClaimsContext : ResultContext<OAuth2IntrospectionOptions>
    {
        /// <summary>
        /// ctor
        /// </summary>
        public ParseExtraClaimsContext(
            HttpContext context,
            AuthenticationScheme scheme,
            OAuth2IntrospectionOptions options)
            : base(context, scheme, options) { }

        /// <summary>
        /// The security token
        /// </summary>
        public JsonElement ParsedJsonResponse { get; set; }
    }
}