/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.Security.Claims;
using System.Threading.Tasks;
using OpenIddict.Abstractions;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server.Tests
{
    public class OpenIddictServerHandlersTests
    {
        [Fact]
        public void DefaultHandlers_ValidateDefaultHandlers()
        {
            // Act and assert
            ImmutableArray<OpenIddictServerHandlerDescriptor> defaultHandlers = OpenIddictServerHandlers.DefaultHandlers;

            Assert.Equal(164, defaultHandlers.Length);
        }

        [Fact]
        public void ValidateAuthenticationDemand_Descriptor_ValidateDescriptor()
        {
            // Arrange

            // Act
            var descriptor = OpenIddictServerHandlers.ValidateAuthenticationDemand.Descriptor;

            // Assert

            Assert.Equal(typeof(ProcessAuthenticationContext), descriptor.ContextType);
            Assert.Equal(-2147383648, descriptor.Order);
            Assert.Empty(descriptor.FilterTypes);
        }

        [Fact]
        public async Task ValidateAuthenticationDemand_HandleWithContextNull_ExceptionExpected()
        {
            // Arrange
            var handler = new OpenIddictServerHandlers.ValidateAuthenticationDemand();

            // Act
            var exception = await Assert.ThrowsAsync<ArgumentNullException>(async () => await handler.HandleAsync(null));

            // Assert
            Assert.Equal("Value cannot be null. (Parameter 'context')", exception.Message);
        }

        [Theory]
        [InlineData(OpenIddictServerEndpointType.Authorization, GrantTypes.AuthorizationCode)]
        [InlineData(OpenIddictServerEndpointType.Logout, GrantTypes.AuthorizationCode)]
        [InlineData(OpenIddictServerEndpointType.Token, GrantTypes.AuthorizationCode)]
        [InlineData(OpenIddictServerEndpointType.Token, GrantTypes.RefreshToken)]
        [InlineData(OpenIddictServerEndpointType.Userinfo, GrantTypes.AuthorizationCode)]
        [InlineData(OpenIddictServerEndpointType.Introspection, GrantTypes.AuthorizationCode)]
        [InlineData(OpenIddictServerEndpointType.Revocation, GrantTypes.AuthorizationCode)]
        public async Task ValidateAuthenticationDemand_HandleWithKnownEndpointType_AmbientPrincipalAttached(OpenIddictServerEndpointType endpointType, string grantType)
        {
            // Arrange
            var handler = new OpenIddictServerHandlers.ValidateAuthenticationDemand();

            ClaimsPrincipal claimsPrincipal = null;
            var transaction = new OpenIddictServerTransaction();
            //if (addClaimsPrincipal)
            //{
            //    claimsPrincipal = new ClaimsPrincipal();
            //    transaction.Properties.Add(Properties.AmbientPrincipal, claimsPrincipal);
            //}

            var context = new ProcessAuthenticationContext(transaction);
            context.Request = new OpenIddictRequest() { GrantType = grantType };
            context.EndpointType = endpointType;

            // Act
            await handler.HandleAsync(context);

            // Assert
            Assert.Equal(claimsPrincipal, context.Principal);
        }

        [Theory]
        [InlineData(OpenIddictServerEndpointType.Unknown)]
        [InlineData(OpenIddictServerEndpointType.Configuration)]
        [InlineData(OpenIddictServerEndpointType.Cryptography)]
        public async Task ValidateAuthenticationDemand_HandleWithUnknownEndpointType_ExceptionExpected(OpenIddictServerEndpointType endpointType)
        {
            // Arrange
            var handler = new OpenIddictServerHandlers.ValidateAuthenticationDemand();

            var transaction = new OpenIddictServerTransaction();
            var context = new ProcessAuthenticationContext(transaction);
            context.EndpointType = endpointType;

            // Act
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () => await handler.HandleAsync(context));

            // Assert
            Assert.Equal("No identity cannot be extracted from this request.", exception.Message);
        }

        [Fact]
        public void AttachDefaultChallengeError_Descriptor_ValidateDescriptor()
        {
            // Arrange

            // Act
            var descriptor = OpenIddictServerHandlers.AttachDefaultChallengeError.Descriptor;

            // Assert

            Assert.Equal(typeof(ProcessChallengeContext), descriptor.ContextType);
            Assert.Equal(-2147383648, descriptor.Order);
            Assert.Empty(descriptor.FilterTypes);
        }

        [Fact]
        public async Task AttachDefaultChallengeError_HandleWithContextNull_ExceptionExpected()
        {
            // Arrange
            var handler = new OpenIddictServerHandlers.AttachDefaultChallengeError();

            // Act
            var exception = await Assert.ThrowsAsync<ArgumentNullException>(async () => await handler.HandleAsync(null));

            // Assert
            Assert.Equal("Value cannot be null. (Parameter 'context')", exception.Message);
        }

        [Theory]
        [InlineData(OpenIddictServerEndpointType.Authorization, Errors.AccessDenied, "The authorization was denied by the resource owner.")]
        [InlineData(OpenIddictServerEndpointType.Token, Errors.InvalidGrant, "The token request was rejected by the authorization server.")]
        [InlineData(OpenIddictServerEndpointType.Userinfo, Errors.InvalidToken, "The access token is not valid or cannot be used to retrieve user information.")]
        public async Task AttachDefaultChallengeError_HandleWithKnownEndpointType_AmbientPrincipalAttached(OpenIddictServerEndpointType endpointType, string expectedError, string expectedErrorDescription)
        {
            // Arrange
            var handler = new OpenIddictServerHandlers.AttachDefaultChallengeError();

            var transaction = new OpenIddictServerTransaction();
            var context = new ProcessChallengeContext(transaction);
            context.Response = new OpenIddictResponse();
            context.EndpointType = endpointType;

            // Act
            await handler.HandleAsync(context);

            // Assert
            Assert.Equal(expectedError, context.Response.Error);
            Assert.Equal(expectedErrorDescription, context.Response.ErrorDescription);
        }

        [Theory]
        [InlineData(OpenIddictServerEndpointType.Unknown, null)]
        [InlineData(OpenIddictServerEndpointType.Unknown, "Dummy")]
        [InlineData(OpenIddictServerEndpointType.Configuration, null)]
        [InlineData(OpenIddictServerEndpointType.Configuration, "Dummy")]
        [InlineData(OpenIddictServerEndpointType.Cryptography, null)]
        [InlineData(OpenIddictServerEndpointType.Cryptography, "Dummy")]
        [InlineData(OpenIddictServerEndpointType.Introspection, null)]
        [InlineData(OpenIddictServerEndpointType.Introspection, "Dummy")]
        [InlineData(OpenIddictServerEndpointType.Logout, null)]
        [InlineData(OpenIddictServerEndpointType.Logout, "Dummy")]
        [InlineData(OpenIddictServerEndpointType.Revocation, null)]
        [InlineData(OpenIddictServerEndpointType.Revocation, "Dummy")]
        public async Task AttachDefaultChallengeError_HandleWithUnknownEndpointType_ExceptionExpected(OpenIddictServerEndpointType endpointType, string errorValue)
        {
            // Arrange
            var handler = new OpenIddictServerHandlers.AttachDefaultChallengeError();

            var transaction = new OpenIddictServerTransaction();
            var context = new ProcessChallengeContext(transaction);
            context.Response = new OpenIddictResponse() { Error = errorValue };
            context.EndpointType = endpointType;

            // Act
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () => await handler.HandleAsync(context));

            // Assert
            Assert.Equal("An OpenID Connect response cannot be returned from this endpoint.", exception.Message);
        }

        [Theory]
        [InlineData(OpenIddictServerEndpointType.Authorization)]
        [InlineData(OpenIddictServerEndpointType.Token)]
        [InlineData(OpenIddictServerEndpointType.Userinfo)]
        [InlineData(OpenIddictServerEndpointType.Unknown)]
        [InlineData(OpenIddictServerEndpointType.Configuration)]
        [InlineData(OpenIddictServerEndpointType.Cryptography)]
        [InlineData(OpenIddictServerEndpointType.Introspection)]
        [InlineData(OpenIddictServerEndpointType.Logout)]
        [InlineData(OpenIddictServerEndpointType.Revocation)]
        public async Task AttachDefaultChallengeError_HandleWithCustomError_KeepCustomError(OpenIddictServerEndpointType endpointType)
        {
            // Arrange
            var handler = new OpenIddictServerHandlers.AttachDefaultChallengeError();

            var transaction = new OpenIddictServerTransaction();
            var context = new ProcessChallengeContext(transaction);
            context.Response = new OpenIddictResponse() { Error = "Dummy", ErrorDescription = "Error" };
            context.EndpointType = endpointType;

            // Act
            await handler.HandleAsync(context);

            // Assert
            Assert.Equal("Dummy", context.Response.Error);
            Assert.Equal("Error", context.Response.ErrorDescription);
        }
    }
}