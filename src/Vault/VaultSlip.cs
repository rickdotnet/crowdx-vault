namespace Vault;

public record VaultSlip
{
    // not used in post or put bodies
    // only used to return the vault id
    public string VaultId { get; init; } = string.Empty;
    public string OwnerKey { get; init; } = string.Empty;
    public string DisplayName { get; init; } = string.Empty;
    public string? Description { get; init; } = string.Empty;
    public string[] Signers { get; set; } = [];
    public DateTimeOffset? Expires { get; init; }
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? UpdatedAt { get; init; }
    
    // vault options
    // ttl, max size, max keys, etc.
}

