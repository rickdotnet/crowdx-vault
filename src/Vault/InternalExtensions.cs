namespace Vault;

internal static class InternalExtensions
{
    public static void AddClaim(this Dictionary<string, List<string>> dict, string key, string value)
    {
        if (!dict.ContainsKey(key))
            dict[key] = [];
        
        if (!dict[key].Contains(value))
            dict[key].Add(value);
    }
}
