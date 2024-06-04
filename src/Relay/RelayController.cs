using Microsoft.AspNetCore.Mvc;
using Nostrfi.Core;

namespace Nostrfi.Relay;

public class RelayController(SocketHandler handler) : ControllerBase
{
    [Route("/")]
    public async Task Socket()
    {
        if (HttpContext.WebSockets.IsWebSocketRequest)
        {
            using var webSocket = await HttpContext.WebSockets.AcceptWebSocketAsync();
            await handler.Handle(webSocket);
           
        }
        else
        {
            HttpContext.Response.StatusCode = StatusCodes.Status400BadRequest;
        }
    }
    
}