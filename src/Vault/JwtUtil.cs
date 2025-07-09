using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using NATS.Jwt;
using NATS.Jwt.Models;
using NATS.NKeys;
using RickDotNet.Base;
using RickDotNet.Extensions.Base;
using RickBase32 = RickDotNet.Base.Utils.Base32;

namespace Vault;

public class JwtUtil
{
    public const string SignerClaimType = "signer";
    public static Result<T> DecodeClaims<T>(string jwt)
        where T : JwtClaimsData
    {
        string[] parts = jwt.Split('.');
        if (parts.Length != 3)
            return Result.Error<T>("Invalid JWT format");

        var header = JsonSerializer.Deserialize<JwtHeader>(EncodingUtils.FromBase64UrlEncoded(parts[0]));
        if (header == null)
            return Result.Error<T>("Can't parse JWT header");

        var validHeader = Result.Try(() => header.Validate());
        if (validHeader is Result<Unit>.Error error)
            return Result.Error<T>($"Invalid JWT header: {error}");

        var payloadJson = EncodingUtils.FromBase64UrlEncoded(parts[1]);
        var claims = JsonSerializer.Deserialize<T>(payloadJson, JsonSerializerOptions.Default);
        if (claims == null)
            return Result.Error<T>("Can't parse JWT claims");

        byte[] signature = EncodingUtils.FromBase64UrlEncoded(parts[2]);

        var verifyResult = VerifyClaims(
            claimsData: claims,
            headerAndPayload: parts[0] + "." + parts[1],
            signature
        );
        
        return verifyResult.Select(_ => claims);

        static Result<Unit> VerifyClaims(JwtClaimsData? claimsData, string headerAndPayload, byte[] signature)
        {
            if (claimsData == null)
                return Result.Error("Invalid JWT: can't parse claims");

            var issuer = claimsData.Issuer;
            if (string.IsNullOrWhiteSpace(issuer))
                return Result.Error("Invalid JWT: can't find issuer");

            var kp = KeyPair.FromPublicKey(issuer.AsSpan());
            return kp.Verify(Encoding.ASCII.GetBytes(headerAndPayload), signature)
                ? Result.Success()
                : Result.Error("JWT signature verification failed");
        }
    }

    public static string Encode<T>(T claim, KeyPair keyPair, DateTimeOffset? now = null)
        where T : JwtClaimsData
    {
        if (string.IsNullOrWhiteSpace(claim.Subject))
            throw new NatsJwtException("Subject is not set");

        claim.Issuer = keyPair.GetPublicKey();
        claim.IssuedAt = now ?? DateTimeOffset.UtcNow;
        claim.Id = Hash<JwtClaimsData>(claim);

        var header = Serialize(NatsJwt.NatsJwtHeader);
        var payload = Serialize(claim);
        var toSign = $"{header}.{payload}";
        var sig = Encoding.ASCII.GetBytes(toSign);
        var signature = new byte[64];
        keyPair.Sign(sig, signature);
        
        var eSig = EncodingUtils.ToBase64UrlEncoded(signature);
        return $"{toSign}.{eSig}";
    }

    private static string Serialize<T>(T data)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(data);
        return EncodingUtils.ToBase64UrlEncoded(bytes);
    }

    private static string Hash<T>(T c)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(c);
        using var sha256 = SHA256.Create();
        var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hasher.AppendData(bytes);
        
        var hashResult = hasher.GetHashAndReset();
        var hashresult2 = SHA256.HashData(bytes);
        var result = RickBase32.ToBase32(hashResult);
        var result2 = RickBase32.ToBase32(hashresult2);
        
        var equal = result == result2;
        return RickBase32.ToBase32(hashResult);
    }

    public static Dictionary<string, List<string>> ParseClaims(Dictionary<string, JsonNode> data)
    {
        var claims = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var kvp in data)
        {
            switch (kvp.Value)
            {
                case JsonValue jsonValue:
                    claims.AddClaim(kvp.Key, jsonValue.ToString());
                    break;
                case JsonArray jsonArray:
                    foreach (var item in jsonArray)
                    {
                        if (item is not JsonValue jsonValue)
                            continue;

                        claims.AddClaim(kvp.Key, jsonValue.ToString());
                    }

                    break;
            }
        }

        return claims;
    }
}