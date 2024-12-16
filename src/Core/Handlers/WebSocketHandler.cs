using System.Collections.Immutable;
using System.Net.WebSockets;
using Microsoft.Extensions.Logging;
using Nostrfi.Core.Connectivity;
using Nostrfi.Core.Interfaces.Connectivity;
using Nostrfi.Core.Interfaces.Handlers;

namespace Nostrfi.Core.Handlers;

public class WebSocketHandler(IStateManager connectionStateManager, ILogger<WebSocketHandler> logger): IWebsocketHandler
{
  public event EventHandler<string> Connected;
  
  private static string Id => Guid.NewGuid().ToString().Replace("-", "");
    public  void OnConnect(WebSocket ws)
    {
        var id = Id;
        logger.LogInformation("Connecting WebSocket : {ConnectionId}", id);
        Connected?.Invoke(this, id);
        connectionStateManager.Add(id, ws);
        logger.LogInformation("WebSocket {ConnectionId} added to list", id);
       
    }

    public void OnDisconnect(WebSocket ws)
    {
        var id = connectionStateManager.Get(ws);
        logger.LogInformation("Removing WebSocket : {ConnectionId}", id);
        connectionStateManager.Remove(id);
        
    }


    public Task ReceiveAsync( WebSocket ws, WebSocketReceiveResult result, string msg)
    {
        var id = connectionStateManager.Get(ws);
        return Task.WhenAll();
    }
    
}