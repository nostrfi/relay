using System.Net.WebSockets;

namespace Nostrfi.Core.Interfaces.Connectivity;

public interface IConnectionManager
{
    Task OnConnected(WebSocket socket);
    Task OnDisconnected(WebSocket socket)
}