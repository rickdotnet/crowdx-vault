using System.Security.Claims;
using NATS.Jwt.Models;
using RickDotNet.Base;
using RickDotNet.Extensions.Base;

namespace Vault;

public record VaultUser
{
    public string SignerKey { get; } = string.Empty;
    public string UserKey { get; }
    public IReadOnlyDictionary<string, string[]> Claims { get; }

    private VaultUser(string signerKey, string userKey, Dictionary<string, string[]> claims)
    {
        SignerKey = signerKey;
        UserKey = userKey;
        Claims = claims;
    }

    public static Result<VaultUser> FromAuthHeader(string header)
    {
        if(string.IsNullOrWhiteSpace(header))
            return Result.Error<VaultUser>("Header is null");
        
        if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return Result.Error<VaultUser>("Invalid Authorization header format");
        
        var token = header.Trim()["Bearer ".Length..].Trim();
        return JwtUtil.DecodeClaims<NatsGenericClaims>(token)
            .Bind(natsClaims =>
            {
                if (natsClaims.Expires < DateTimeOffset.UtcNow)
                    return Result.Error<VaultUser>("JWT token expired");

                var jwtClaims = JwtUtil.ParseClaims(natsClaims.Data);
                jwtClaims.AddClaim(ClaimTypes.Name, natsClaims.Subject);
                jwtClaims.AddClaim(JwtUtil.SignerClaimType, natsClaims.Issuer);

                var vaultClaims = jwtClaims.ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value.ToArray()
                );
                
                return new VaultUser(natsClaims.Issuer, natsClaims.Subject, vaultClaims);
            });
    }
}

public static class VaultUserExtensions
{
    public static bool HasVaultAdmin(this VaultUser user, string vaultName) 
        => user.HasClaim("vault:admin", vaultName);

    public static bool HasVaultWriter(this VaultUser user, string vaultName) 
        => user.HasVaultAdmin(vaultName) 
           || user.HasClaim("vault:write", vaultName);

    public static bool HasVaultReader(this VaultUser user, string vaultName) 
        => user.HasVaultWriter(vaultName) 
           || user.HasClaim("vault:read", vaultName);

    public static bool HasKeyAdmin(this VaultUser user, string vaultName, string keyName) 
        => user.HasClaim("key:admin", $"{vaultName}/{keyName}");

    public static bool HasKeyWriter(this VaultUser user, string vaultName, string keyName) 
        => user.HasKeyAdmin(vaultName, keyName) 
           || user.HasClaim("key:write", $"{vaultName}/{keyName}");

    public static bool HasKeyReader(this VaultUser user, string vaultName, string keyName) 
        => user.HasKeyWriter(vaultName, keyName) 
           || user.HasClaim("key:read", $"{vaultName}/{keyName}");

    private static bool HasClaim(this VaultUser user, string claimType, string claimValue) 
        => user.Claims.TryGetValue(claimType, out var claims) && claims.Contains(claimValue);
}
