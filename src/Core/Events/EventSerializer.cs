using System.Text.Json;
using System.Text.Json.Serialization;
using Nostrfi.Core.Interfaces.Events;
using Nostrfi.Models;

namespace Nostrfi.Core.Events;

public class EventSerializer : IEventSerializer
{
    public Event Deserialize(string message)
    {
        if (string.IsNullOrEmpty(message))
            throw new ArgumentNullException(CoreErrorMessages.EmptyString);
       
        var note = JsonSerializer
            .Deserialize<Event>(message, SerializationOptions);

        return note;
    }
    
    private static JsonSerializerOptions SerializationOptions => new()
    {
        ReferenceHandler = ReferenceHandler.Preserve,           
        WriteIndented = true,                                  
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
    };
}