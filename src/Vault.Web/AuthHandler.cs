using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using NATS.Client.Core;
using RickDotNet.Base;

namespace Vault.Web;

public class AuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly INatsConnection nats;

    [Obsolete("Obsolete ")]
    public AuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock, INatsConnection nats)
        : base(options, logger, encoder, clock)
    {
        this.nats = nats;
    }

    public AuthHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        INatsConnection nats
    )
        : base(options, logger, encoder)
    {
        this.nats = nats;
    }

    /// <summary>
    /// This method simply validates the JWT token and extracts claims from it.
    /// It does not check if the user has access to the requested vault or key.
    /// That is done via the authorization policy.
    /// </summary>
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.ContainsKey("Authorization"))
            return Task.FromResult(AuthenticateResult.NoResult());

        var authHeader = Request.Headers.Authorization.FirstOrDefault(x => x != null && x.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase));
        if (string.IsNullOrEmpty(authHeader))
            return Task.FromResult(AuthenticateResult.Fail("Invalid Authorization header"));

        var vaultUser = VaultUser.FromAuthHeader(authHeader);
        if (vaultUser is Result<VaultUser>.Error error)
            return Task.FromResult(AuthenticateResult.Fail(error.ErrorMessage));

        var actualVaultUser = vaultUser.ValueOrDefault()!;

        var claims = actualVaultUser.Claims
            .SelectMany(c => c.Value.Select(v => new Claim(c.Key, v)))
            .ToArray();

        var claimsIdentity = new ClaimsIdentity(claims, Scheme.Name);
        var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

        var ticket = new AuthenticationTicket(claimsPrincipal, Scheme.Name);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}

static class ClaimsPrincipalExtensions
{

    public static bool HasVaultAdmin(this ClaimsPrincipal principal, string vaultName)
        => principal.HasClaim("vault:admin", vaultName);

    public static bool HasVaultWriter(this ClaimsPrincipal principal, string vaultName)
        => principal.HasVaultAdmin(vaultName) || principal.HasClaim("vault:write", vaultName);

    public static bool HasVaultReader(this ClaimsPrincipal principal, string vaultName)
        => principal.HasVaultWriter(vaultName) || principal.HasClaim("vault:read", vaultName);

    public static bool HasKeyAdmin(this ClaimsPrincipal principal, string vaultName, string keyName)
        => principal.HasClaim("key:admin", $"{vaultName}/{keyName}");

    public static bool HasKeyWriter(this ClaimsPrincipal principal, string vaultName, string keyName)
        => principal.HasKeyAdmin(vaultName, keyName) || principal.HasClaim("key:write", $"{vaultName}/{keyName}");

    public static bool HasKeyReader(this ClaimsPrincipal principal, string vaultName, string keyName)
        => principal.HasKeyWriter(vaultName, keyName) || principal.HasClaim("key:read", $"{vaultName}/{keyName}");


    public static bool HasClaim(this ClaimsPrincipal principal, string claimType, string claimValue)
    {
        return principal.Claims.Any(c => c.Type == claimType && c.Value == claimValue);
    }
}
