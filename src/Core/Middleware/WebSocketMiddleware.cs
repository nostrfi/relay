using System.Net.WebSockets;
using System.Text;
using Microsoft.AspNetCore.Http;
using Nostrfi.Core.Handlers;
using Nostrfi.Core.Interfaces.Handlers;

namespace Nostrfi.Core.Middleware;

public class WebSocketMiddleware(RequestDelegate next, IWebsocketHandler webSocketHandler)
{
    private readonly byte[] _buffer = new byte[1024 * 4];
    
    public async Task InvokeAsync(HttpContext context)
    {
        if (context.WebSockets.IsWebSocketRequest)
        {
            var webSocket = await context.WebSockets.AcceptWebSocketAsync();
             webSocketHandler.OnConnect(webSocket);
             
            await Receive(webSocket, async (result, buffer) =>
            {
                switch (result.MessageType)
                {
                    case WebSocketMessageType.Text:
                        await webSocketHandler.ReceiveAsync(webSocket, result, buffer);
                        return;
                    case WebSocketMessageType.Close:
                         webSocketHandler.OnDisconnect(webSocket);
                        return;
                    case WebSocketMessageType.Binary:
                        break;
                    default:
                        throw new ArgumentOutOfRangeException();
                }
            });
            
           
     
        }

        await next(context);
    }


    private const int BufferSize = 4 * 1024; // Introduced variable for buffer size

    private async Task Receive(WebSocket webSocket, Action<WebSocketReceiveResult, string> handleMessageCallback)
    {
        while (webSocket.State == WebSocketState.Open)
        {
            try
            {
                var message = await ReadWebSocketMessageAsync(webSocket);
                if (message == null) continue;
                var result = await webSocket
                    .ReceiveAsync(new ArraySegment<byte>(new byte[BufferSize]), CancellationToken.None)
                    .ConfigureAwait(false);
                handleMessageCallback(result, message);
            }
            catch (WebSocketException e)
            {
                if (e.WebSocketErrorCode == WebSocketError.ConnectionClosedPrematurely)
                {
                    webSocket.Abort();
                }
            }
        }

        webSocketHandler.OnDisconnect(webSocket);
    }

    private static async Task<string> ReadWebSocketMessageAsync(WebSocket webSocket)
    {
        var buffer = new ArraySegment<byte>(new byte[BufferSize]);

        await using var ms = new MemoryStream();
        WebSocketReceiveResult result;

        do
        {
            result = await webSocket.ReceiveAsync(buffer, CancellationToken.None).ConfigureAwait(false);
            ms.Write(buffer.Array, buffer.Offset, result.Count);
        } while (!result.EndOfMessage);

        ms.Seek(0, SeekOrigin.Begin);
        using var reader = new StreamReader(ms, Encoding.UTF8);
        return await reader.ReadToEndAsync().ConfigureAwait(false);
    }
}
