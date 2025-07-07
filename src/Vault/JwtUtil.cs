using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using NATS.Jwt;
using NATS.Jwt.Models;
using NATS.NKeys;
using RickDotNet.Base;
using RickDotNet.Extensions.Base;

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
            if (!kp.Verify(Encoding.ASCII.GetBytes(headerAndPayload), signature))
                return Result.Error("JWT signature verification failed");

            return Result.Success();
        }
    }

    public static string Encode<T>(T claim, KeyPair keyPair, DateTimeOffset? now = null)
        where T : JwtClaimsData
    {
        var h = Serialize(NatsJwt.NatsJwtHeader);
        var c = claim;

        if (string.IsNullOrWhiteSpace(c.Subject))
        {
            throw new NatsJwtException("Subject is not set");
        }

        string issuer = keyPair.GetPublicKey();

        c.Issuer = issuer;
        c.IssuedAt = now ?? DateTimeOffset.UtcNow;
        c.Id = Hash<JwtClaimsData>(c);

        var payload = Serialize(c);
        var toSign = $"{h}.{payload}";
        var sig = Encoding.ASCII.GetBytes(toSign);
        var signature = new byte[64];
        keyPair.Sign(sig, signature);
        var eSig = EncodingUtils.ToBase64UrlEncoded(signature);

        return $"{toSign}.{eSig}";
    }

    private static string Serialize<T>(T data)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(data);
        //JsonSerializer.Serialize(jsonWriter, data);
        return EncodingUtils.ToBase64UrlEncoded(bytes);
    }

    private static string Hash<T>(T c)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(c);

        // TODO: ID generation same as Go implementation
        // It's just an ID so we can use SHA-256
        // var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        // hasher.AppendData(bytes);
        // var hashResult = hasher.GetHashAndReset();
        var hashResult = Sha512256.ComputeHash(bytes);

        Span<char> hashResultChars = stackalloc char[Base32.GetEncodedLength(hashResult)];
        Base32.ToBase32(hashResult, hashResultChars);
        return hashResultChars.ToString();
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