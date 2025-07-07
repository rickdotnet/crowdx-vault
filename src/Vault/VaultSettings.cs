namespace Vault;

public record VaultSettings
{
    public string NatsUrl { get; init; } = "nats://localhost:4222";
    public string? NatsUser { get; init; }
    public string? NatsPass { get; init; }
    public string? IssuerKey { get; init; }
    public string? IssuerSeed { get; init; }
}
