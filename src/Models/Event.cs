using System.Text.Json.Serialization;
using Nostrfi.Models.Convertors;

namespace Nostrfi.Models;

public class Event
{
        /// <summary>
        /// 32-bytes lowercase hex-encoded sha256 of the serialized event data
        /// </summary>
        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;

        /// <summary>
        /// 32-bytes lowercase hex-encoded public key of the event creator
        /// </summary>
        [JsonPropertyName("pubkey")]
        public string PubKey { get; set; } = string.Empty;

        /// <summary>
        /// unix timestamp in second
        /// </summary>
        [JsonPropertyName("created_at")]
        [JsonConverter(typeof(UnixTimeStampJsonConvertor))]
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// integer between 0 and 65535
        /// </summary>
        [JsonPropertyName("kind")]
        public int Kind { get; set; }

        /// <summary>
        /// arbitrary string
        /// </summary>
        [JsonPropertyName("content")]
        public string Content { get; set; } = string.Empty;

        /// <summary>
        /// 64-bytes lowercase hex of the signature of the sha256 hash of the serialized event data, which is the same as the "id" field
        /// </summary>
        [JsonPropertyName("sig")]
        public string Sig { get; set; } = string.Empty;
        
        
        /// <summary>
        /// Each tag is an array of one or more strings, with some conventions around them
        /// </summary>
        [JsonPropertyName("tags")]
        public List<string[]> Tags { get; set; } = [];
    
}