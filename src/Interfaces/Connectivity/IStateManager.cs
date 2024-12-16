using System.Net.WebSockets;

namespace Nostrfi.Core.Interfaces.Connectivity;

public interface IStateManager
{
    void Add(string connection, WebSocket ws);
    Task Remove(string connection);
    string Get(WebSocket ws);
}