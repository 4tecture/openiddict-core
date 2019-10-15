using Microsoft.Extensions.Logging.Abstractions;
using OpenIddict.Abstractions;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers.Authentication;

namespace OpenIddict.Server.Tests
{
    public static class OpenIddictServerHandlersTests
    {
        public class Authentication
        {
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
}
