namespace Vault;

public record VaultSettings
{
    public string NatsUrl { get; init; } = "nats://localhost:4222";
    public string IssuerKey { get; init; } = "ACBEED26BZNEL3EKFSK4UKITTJOQZPP4HJBAGI4VNXUCDKPKNTNN2NUA";
    public string IssuerSeed { get; init; } = "SAAAE2JMCZNPDPRS3AKEAW6UZFNM3BBFETKF2SYBF6G37ZWYINHP5LMP6M";
    public string? NatsUser { get; init; }
    public string? NatsPass { get; init; }
}
