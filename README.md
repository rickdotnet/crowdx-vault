# crowdx-vault

## Overview

This is an experimental key-vault server that allows for decentralized access-control.

### Prerequisites

- NATS Server with JetStream enabled
  - `docker run -d nats:latest -js`

### Running

Tbd, but essentially have NATS running and then run the `Vault.Web` project.
![image](https://github.com/user-attachments/assets/23d1e983-9f36-4002-b67b-353027922404)

## Usage

### Create a Key Pair

The home page has a testing key pair generated for quick testing.

From code:
```csharp
var keyPair = KeyPair.CreatePair(PrefixByte.Account);
Console.WriteLine(keyPair.GetSeed());
Console.WriteLine(keyPair.GetPublicKey());
var claims = new NatsGenericClaims
{
    Subject = keyPair.GetPublicKey(),
    Expires = DateTimeOffset.UtcNow.AddMonths(6)
};

// create the vault
var vaultToken = JwtUtil.Encode(claims, keyPair);
claims.Data = new Dictionary<string, JsonNode>()
{
    { "vault:admin", "replace-with-vault-id" }
};

// once the vault is created, create an admin token
var adminToken = JwtUtil.Encode(claims, keyPair);

```

### Access Levels

**Vault-level:**
- `vault:admin` - Admin access to the vault (delete, write, read)
- `vault:write` - Write access to the vault (write, read)
- `vault:read` - Read access to the vault

**Key-level:**
- `key:admin` - Admin access to the key (delete, write, read)
- `key:write` - Write access to the key (write, read)
- `key:read` - Read access to the key

### Create a Vault

Send a `POST` request to the `/kv` endpoint with a JWT token in the Authorization header.
After creation, generate a new JWT with the returned vault ID in the `vault:admin` claim.

```bash
curl -X POST https://localhost:7241/kv \
  -H "Authorization: Bearer <your-jwt>" \
  -H "Content-Type: application/json" \
  -d '{"displayName": "Test Vault", "description": "A test vault"}'
```

### Store a Value

Use the vault Id from the previous step in the URL and a JWT with appropriate access to store a key-value pair.
See the C# code snippet above for generating the JWT.
 
```bash
curl -X PUT https://localhost:7241/kv/{vault}/foo \
  -H "Authorization: Bearer <your-jwt>" \
  -H "Content-Type: application/json" \
  -d '{"foo": "bar"}'
```

### Retrieving a Value

Fetch a value using a `GET` request with a valid JWT. *Piped to `xxd` for readability.*

```bash
curl -X GET https://localhost:7241/kv/{vault}/foo \
  -H "Authorization: Bearer <your-jwt>" | xxd
```

### Deleting a Value

Remove a value with a `DELETE` request and a JWT with sufficient permissions.

```bash
curl -X DELETE https://localhost:7241/kv/{vault}/foo \
  -H "Authorization: Bearer <your-jwt>"

```

### Deleting a Vault

Delete a vault using a `DELETE` request with a JWT bearing `vault:admin` permissions.

```bash
curl -X DELETE https://localhost:7241/kv/{vault} \
  -H "Authorization: Bearer <your-jwt>"
```
