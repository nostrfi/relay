using Nostrfi.Models;

namespace Nostrfi.Core.Events;

public interface IEventSerializer
{
    Event Serialize(string message);
}