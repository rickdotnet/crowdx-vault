using System.Text.Json.Nodes;
using NATS.Jwt.Models;
using NATS.NKeys;
using RickDotNet.Base;
using RickDotNet.Extensions.Base;

namespace Vault;

public record MintedVaultJwt
{
    public required VaultJwtInfo Info { get; init; }
    public string Token { get; init; } = string.Empty;

    public static Result<MintedVaultJwt> Mint(VaultJwtInfo info, KeyPair keyPair)
        => new MintedVaultJwt { Info = info, Token = info.MintToken(keyPair) };

    public static Result<MintedVaultJwt> FromToken(string token)
        => VaultJwtInfo.FromToken(token).Select(i => new MintedVaultJwt { Info = i, Token = token });
}
public record VaultJwtInfo
{
    public string Subject { get; init; } = string.Empty;
    public DateTimeOffset? IssuedAt { get; init; }
    public DateTimeOffset? Expires { get; init; }
    public Dictionary<string, JsonNode> Claims { get; init; } = new();
    
    public string MintToken(KeyPair keyPair)
    {
        var natsClaims = new NatsGenericClaims
        {
            Subject = Subject,
            IssuedAt = IssuedAt,
            Expires = Expires,
            Data = Claims
        };

        return JwtUtil.Encode(natsClaims, keyPair);
    }
    
    public static Result<VaultJwtInfo> FromToken(string token)
    {
        return Result.Try(() =>
        {
            var natsClaims = JwtUtil.DecodeClaims<NatsGenericClaims>(token);
            return natsClaims.Select(claims => new VaultJwtInfo
            {
                Subject = claims.Subject,
                IssuedAt = claims.IssuedAt,
                Expires = claims.Expires,
                Claims = claims.Data
            });
        });
    }
}
