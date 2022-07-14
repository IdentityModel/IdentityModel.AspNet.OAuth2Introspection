using System.Security.Claims;
using System.Text.Json;
using IdentityModel.AspNetCore.OAuth2Introspection;
using IdentityModel.AspNetCore.OAuth2Introspection.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Tests.Util;
using Xunit;

namespace Tests
{
    public static class Unit
    {
        [Theory]
        [InlineData(null, "key:")]
        [InlineData("", "key:")]
        [InlineData(" ", "key:")]
        [InlineData("abcdefg01234", "key:9/+6X7C6m2lsSY7l+QUPZ8WP88j03/JP3iTSUUFqJBY=")]
        [InlineData("0123456789012345678901234567890123456789", "key:+1Js1K0OyXjBqeePfAcocRE5l4Qk1hjrIovlniEYiXA=")]
        public static void CacheKey_From_Token(string input, string expected)
        {
            var opts = new OAuth2IntrospectionOptions { CacheKeyPrefix = "key:" };
            var key = CacheUtils.CacheKeyFromToken()(opts, input);
            Assert.Equal(expected, key);
        }

        [Fact]
        public static void CacheKey_From_Long_Token()
        {
            const string token =
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4g" +
                "RG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5ceyJhbGc" +
                "iOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiw" +
                "iaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5ceyJhbGciOiJIUz" +
                "I1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0I" +
                "joxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

            var opts = new OAuth2IntrospectionOptions { CacheKeyPrefix = "" };
            var key = CacheUtils.CacheKeyFromToken()(opts, token);
            Assert.Equal("isDF1Tx4u6Fm+T7JQ2gK3yUimvGzy7jF1e7X79vDVTs=", key);
        }

        [Theory]
        [InlineData(null, new string[] { })]
        [InlineData(null, new string[] { "Basic XYZ" })]
        [InlineData(null, new string[] { "Basic XYZ", "Bearer ABC" })]
        [InlineData("ABC", new string[] { "Bearer ABC" })]
        [InlineData("ABC", new string[] { "Bearer  ABC " })]
        [InlineData("ABC", new string[] { "Bearer ABC", "Basic XYZ" })]
        [InlineData("ABC", new string[] { "Bearer ABC", "Bearer DEF" })]
        [InlineData("ABC", new string[] { "Bearer    ABC", "Bearer DEF" })]
        [InlineData("ABC", new string[] { "Bearer ABC   ", "Bearer DEF" })]
        public static void Token_From_Header(string expected, string[] headerValues)
        {
            var request = new MockHttpRequest();
            request.Headers.Add("Authorization", new Microsoft.Extensions.Primitives.StringValues(headerValues));

            var actual = TokenRetrieval.FromAuthorizationHeader()(request);
            Assert.Equal(expected, actual);
        }

        [Theory]
        [InlineData(null, "?a=1")]
        [InlineData("", "?access_token=")]
        [InlineData("", "?access_token&access_token")]
        [InlineData("xyz", "?access_token=xyz")]
        [InlineData("xyz", "?a=1&access_token=xyz")]
        [InlineData("abc", "?access_token=abc&access_token=xyz")]
        public static void Token_From_Query(string expected, string queryString)
        {
            var request = new MockHttpRequest
            {
                Query = new QueryCollection(QueryHelpers.ParseQuery(queryString))
            };

            var actual = TokenRetrieval.FromQueryString()(request);
            Assert.Equal(expected, actual);
        }
    }
}
