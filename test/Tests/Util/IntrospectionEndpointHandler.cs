﻿// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Tests.Util
{
    class IntrospectionEndpointHandler : DelegatingHandler
    {
        private readonly Behavior _behavior;

        public enum Behavior
        {
            Active,
            Inactive,
            Unauthorized
        }

        public bool SentIntrospectionRequest { get; set; } = false;

        public Dictionary<string, object> AdditionalValues { get; set; } = new Dictionary<string, object>();
        public string IntrospectionEndpoint { get; set; }
        public string DiscoveryEndpoint { get; set; }
        public bool IsDiscoveryFailureTest { get; set; } = false;

        public IntrospectionEndpointHandler(Behavior behavior, TimeSpan? ttl = null)
        {
            _behavior = behavior;

            if (ttl.HasValue)
            {
                AdditionalValues.Add("exp", DateTimeOffset.UtcNow.Add(ttl.Value).ToUnixTimeSeconds());
            }
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri.AbsoluteUri.Contains("well-known"))
            {
                return SendDiscoveryAsync(request, cancellationToken);
            }
            else
            {
                return SendIntrospectionAsync(request, cancellationToken);
            }
        }

        protected Task<HttpResponseMessage> SendDiscoveryAsync(HttpRequestMessage request, System.Threading.CancellationToken cancellationToken)
        {
            if (IsDiscoveryFailureTest)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            }

            if (request.RequestUri.AbsoluteUri.ToString() == "https://authority.com/.well-known/openid-configuration")
            {
                DiscoveryEndpoint = request.RequestUri.AbsoluteUri;

                var data = new Dictionary<string, object>
                {
                    { "issuer", "https://authority.com" },
                    { "introspection_endpoint", "https://authority.com/introspection_endpoint" }
                };

                var json = SimpleJson.SimpleJson.SerializeObject(data);

                var response = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(json, Encoding.UTF8, "application/json")
                };

                return Task.FromResult(response);
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        protected Task<HttpResponseMessage> SendIntrospectionAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            SentIntrospectionRequest = true;
            IntrospectionEndpoint = request.RequestUri.AbsoluteUri;

            if (_behavior == Behavior.Unauthorized)
            {
                var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
                return Task.FromResult(response);
            }
            if (_behavior == Behavior.Active)
            {
                var responseObject = new Dictionary<string, object>
                {
                    { "active", true }
                };

                foreach (var item in AdditionalValues)
                {
                    responseObject.Add(item.Key, item.Value);
                }

                var json = SimpleJson.SimpleJson.SerializeObject(responseObject);

                var response = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(json, Encoding.UTF8, "application/json")
                };

                return Task.FromResult(response);
            }
            if (_behavior == Behavior.Inactive)
            {
                var responseObject = new Dictionary<string, object>
                {
                    { "active", false }
                };

                var json = SimpleJson.SimpleJson.SerializeObject(responseObject);

                var response = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(json, Encoding.UTF8, "application/json")
                };

                return Task.FromResult(response);
            }

            throw new NotImplementedException();
        }
    }
}