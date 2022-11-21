// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
#if NET6_0_OR_GREATER
using System.Buffers;
#endif

namespace IdentityModel.AspNetCore.OAuth2Introspection
{
    internal static class StringExtensions
    {
        [DebuggerStepThrough]
        public static string EnsureTrailingSlash(this string input)
        {
            if (!input.EndsWith("/"))
            {
                return input + "/";
            }

            return input;
        }

        [DebuggerStepThrough]
        public static bool IsMissing(this string value)
        {
            return string.IsNullOrWhiteSpace(value);
        }

        [DebuggerStepThrough]
        public static bool IsPresent(this string value)
        {
            return !string.IsNullOrWhiteSpace(value);
        }

        /// <summary>
        /// Returns Base64 UTF8 bytes of <paramref name="input"/> appended to <paramref name="prefix"/>.
        /// If <paramref name="input"/> is missing, returns only prefix.
        /// </summary>
        internal static string Sha256(this string input, string prefix)
        {
            if (input.IsMissing()) return prefix;

#if !NET6_0_OR_GREATER
            using var sha = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(input);
            var hash = sha.ComputeHash(bytes);
            return prefix + Convert.ToBase64String(hash);
#else
            const int Base64Sha256Len = 44; // base64 sha256 is always 44 chars
            return string.Create(prefix.Length + Base64Sha256Len, (input, prefix), _sha256WithPrefix);
#endif
        }

#if NET6_0_OR_GREATER
        private static readonly SpanAction<char, (string input, string prefix)> _sha256WithPrefix = Sha256WithPrefix;

        /// <summary>
        /// Writes prefix with input's sha256 hash as base64 appended to the span.
        /// </summary>
        private static void Sha256WithPrefix(Span<char> destination, (string input, string prefix) state)
        {
            const int Sha256Len = 32; // sha256 is always 32 bytes
            const int MaxStackAlloc = 256;

            var (input, prefix) = state;

            // use a rented buffer if input as bytes would be dangerously long to stackalloc
            byte[] rented = null;

            try
            {
                int maxUtf8Len = Encoding.UTF8.GetMaxByteCount(input.Length);

                Span<byte> utf8buffer = maxUtf8Len > MaxStackAlloc
                    ? (rented = ArrayPool<byte>.Shared.Rent(maxUtf8Len))
                    : stackalloc byte[maxUtf8Len];

                int utf8Written = Encoding.UTF8.GetBytes(input, utf8buffer);

                Span<byte> hashBuffer = stackalloc byte[Sha256Len];
                int hashedCount = SHA256.HashData(utf8buffer[..utf8Written], hashBuffer);
                Debug.Assert(hashedCount == Sha256Len);

                if (prefix.Length != 0)
                    prefix.CopyTo(destination);

                bool b64success = Convert.TryToBase64Chars(hashBuffer, destination[prefix.Length..], out var b64written);
                Debug.Assert(b64success);
            }
            finally
            {
                if (rented != null)
                    ArrayPool<byte>.Shared.Return(rented);
            }
        }
#endif
    }
}