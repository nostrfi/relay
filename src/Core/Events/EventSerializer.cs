using Nostrfi.Models;

namespace Nostrfi.Core.Events;

public class EventSerializer : IEventSerializer
{
    public Event Serialize(string message)
    {
        if (string.IsNullOrEmpty(message))
            throw new ArgumentNullException(CoreErrorMessages.EmptyString);


        var note = System.Text.Json.JsonSerializer
            .Deserialize<Event>(message);

        return note;
    }
}