using System.Text.Json.Serialization;

namespace Nostrfi.Models;

public class Event
{
        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;

        [JsonPropertyName("pubkey")]
        public string PubKey { get; set; } = string.Empty;

        [JsonPropertyName("created_at")]
        [JsonConverter(typeof(UnixTimeStampJsonConvertor))]
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        [JsonPropertyName("kind")]
        public int Kind { get; set; }

        [JsonPropertyName("content")]
        public string Content { get; set; } = string.Empty;

        [JsonPropertyName("sig")]
        public string Sig { get; set; } = string.Empty;
        [JsonPropertyName("tags")]
        public List<string[]> Tags { get; set; } = new List<string[]>();
    
}