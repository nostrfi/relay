using System.Net.WebSockets;

namespace Nostrfi.Core.Interfaces.Handlers;

public interface IWebsocketHandler
{
    event EventHandler<string> Connected;
    void OnConnect(WebSocket ws);
    void OnDisconnect(WebSocket ws);
    Task ReceiveAsync(WebSocket ws, WebSocketReceiveResult result, string msg);
}