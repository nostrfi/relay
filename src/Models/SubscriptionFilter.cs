using System.Text.Json;
using System.Text.Json.Serialization;
using Nostrfi.Models.Convertors;

namespace Nostrfi.Models;

public class SubscriptionFilter
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("ids")] 
    public string[] Ids { get; set; }
    
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("authors")] 
    public string[] Authors { get; set; }
    
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("kinds")] 
    public int[] Kinds { get; set; }
    
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("#e")] 
    public string[] ReferencedEventIds { get; set; }
    
    
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("#p")] 
    public string[] ReferencedPublicKeys { get; set; }
    
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("since")]
    [JsonConverter(typeof(UnixTimeStampJsonConvertor))]
    public DateTimeOffset? Since { get; set; }
    
    
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("until")]
    [JsonConverter(typeof(UnixTimeStampJsonConvertor))] 
    public DateTimeOffset? Until { get; set; }
    
    
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("limit")] 
    public int Limit { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonExtensionData]
    public IDictionary<string, JsonElement> ExtensionData { get; set; }

    public Dictionary<string, string[]> GetAdditionalTagFilters()
    {
        var tagFilters = ExtensionData?.Where(pair => pair.Key.StartsWith("#") && pair.Value.ValueKind == JsonValueKind.Array);
        return tagFilters?.ToDictionary(tagFilter => tagFilter.Key[1..],
            tagFilter => tagFilter.Value.EnumerateArray().Select(element => element.GetString())
                .ToArray())! ?? new Dictionary<string, string[]>();
    }
}