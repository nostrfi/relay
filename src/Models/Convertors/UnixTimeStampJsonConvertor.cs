using System.Text.Json;
using System.Text.Json.Serialization;

namespace Nostrfi.Models.Convertors;

public class UnixTimeStampJsonConvertor : JsonConverter<DateTimeOffset>
{
    public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert,
        JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.Number) throw new JsonException(ModelsErrorMessages.NotANumber)
            {
                Source = nameof(Read)
            };
        
        return DateTimeOffset.FromUnixTimeSeconds(reader.GetInt64());
    }

    public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options)
    {
       writer.WriteNumberValue(value.ToUnixTimeSeconds());
    }
}