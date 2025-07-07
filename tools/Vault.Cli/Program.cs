using System.Text.Json;
using System.Text.Json.Nodes;
using NATS.Jwt.Models;
using NATS.NKeys;
using Spectre.Console;
using Vault;


//var keyPair = KeyPair.FromSeed("SAADUVDJ22KHLGAU47QIQHBFW6GWDZ55S2L45BXF6UW3AV5XXNVUKFYMJ4");
var keyPair = KeyPair.CreatePair(PrefixByte.Account);
Console.WriteLine(keyPair.GetSeed());
Console.WriteLine(keyPair.GetPublicKey());
var claims = new NatsGenericClaims
{
    Subject = keyPair.GetPublicKey(), // could be different from the signer
    Expires = DateTimeOffset.UtcNow.AddMonths(6)
};

var vaultToken = JwtUtil.Encode(claims, keyPair);
claims.Data = new Dictionary<string, JsonNode>()
{
    { "vault:admin", "G5HEDQ2B4DPGUUA" }
};

var adminToken = JwtUtil.Encode(claims, keyPair);


var vaultJwt = MintedVaultJwt.FromToken(adminToken);

var rawClaims = JwtUtil.DecodeClaims<NatsGenericClaims>(adminToken).ValueOrDefault();
var parsedClaims = JwtUtil.ParseClaims(rawClaims?.Data ?? new Dictionary<string, JsonNode>());

return;

var currentDirectory = Directory.GetCurrentDirectory();
var configPath = Path.Combine(currentDirectory, "vaultSettings.json");
if (!File.Exists(configPath))
{
    var userDirectory = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    configPath = Path.Combine(userDirectory, ".vault", "vaultSettings.json");
}

VaultSettings vaultSettings = File.Exists(configPath)
    ? ConfigFromFile(configPath)
    : ConfigFromPrompt();

var saveConfig = AnsiConsole.Confirm("Save settings to file?");
if (saveConfig)
{
    Directory.CreateDirectory(Path.GetDirectoryName(configPath)!);
    var json = JsonSerializer.Serialize(vaultSettings, new JsonSerializerOptions { WriteIndented = true });
    File.WriteAllText(configPath, json);
    AnsiConsole.MarkupLine($"Settings saved to [green]{configPath}[/]");
}
else
{
    AnsiConsole.MarkupLine("Configuration not saved.");
}

return;

// var host = Host.CreateApplicationBuilder(args).ConfigureHost();
// host.Run();
static VaultSettings ConfigFromFile(string configPath)
{
    if (!File.Exists(configPath))
    {
        throw new FileNotFoundException($"Configuration file not found: {configPath}");
    }

    var json = File.ReadAllText(configPath);
    return JsonSerializer.Deserialize<VaultSettings>(json) ?? throw new InvalidOperationException("Failed to deserialize vaultSettings");
}

static VaultSettings ConfigFromPrompt()
    => new()
    {
        IssuerSeed = AnsiConsole.Ask("Vault Seed", ""),
        NatsUrl = AnsiConsole.Ask("NATS URL", "nats://localhost:4222"),
        NatsUser = AnsiConsole.Ask("NATS User", "vaultuser"),
        NatsPass = AnsiConsole.Ask("NATS Password", "vaultpass")
    };
