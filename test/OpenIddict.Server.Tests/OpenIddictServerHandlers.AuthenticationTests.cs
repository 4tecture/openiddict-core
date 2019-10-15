/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using OpenIddict.Abstractions;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers.Authentication;

namespace OpenIddict.Server.Tests
{
    public class OpenIddictServerHandlers_AuthenticationTests
    {
        [Fact]
        public void DefaultHandlers_ValidateDefaultHandlers()
        {
            // Act and assert
            ImmutableArray<OpenIddictServerHandlerDescriptor> defaultHandlers = OpenIddictServerHandlers.Authentication.DefaultHandlers;

            Assert.Equal(29, defaultHandlers.Length);
        }

        [Fact]
        public async Task Authentication_ValidateRedirectUriParameter_RejectsEmptyRedirectUriWithOpenIdScope()
        {
            // Arrange
            var transaction = new OpenIddictServerTransaction
            {
                Logger = NullLogger.Instance,
                Options = new OpenIddictServerOptions(),
                Request = new OpenIddictRequest
                {
                    RedirectUri = null,
                    Scope = Scopes.OpenId
                }
            };

            var context = new ValidateAuthorizationRequestContext(transaction);
            var handler = new ValidateRedirectUriParameter();

            // Act
            await handler.HandleAsync(context);

            // Assert
            Assert.True(context.IsRejected);
            Assert.Equal(Errors.InvalidRequest, context.Error);
            Assert.Equal("The mandatory 'redirect_uri' parameter is missing.", context.ErrorDescription);
        }

        [Fact]
        public async Task Authentication_ValidateRedirectUriParameter_ThrowsAnExceptionForNullContext()
        {
            // Arrange
            var transaction = new OpenIddictServerTransaction
            {
                Logger = NullLogger.Instance,
                Options = new OpenIddictServerOptions(),
                Request = new OpenIddictRequest
                {
                    RedirectUri = null,
                    Scope = Scopes.OpenId
                }
            };

            ValidateAuthorizationRequestContext context = null;
            var handler = new ValidateRedirectUriParameter();

            // Act and assert
            var exception = await Assert.ThrowsAsync<ArgumentNullException>(async () => await handler.HandleAsync(context));
            Assert.Equal("context", exception.ParamName);
        }
    }
}