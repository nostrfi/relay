using Nostrfi.Models;

namespace Nostrfi.Core.Interfaces.Events;

public interface IEventSerializer
{
    Event Deserialize(string message);
}