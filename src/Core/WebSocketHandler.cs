using System.Net.WebSockets;
using System.Text;
using Nostrfi.Core.Events;
using Nostrfi.Models;

namespace Nostrfi.Core;

public class WebSocketHandler(IEventSerializer serializer)
{
    private readonly byte[] _buffer = new byte[1024 * 4];

    public async Task Handle(WebSocket ws)
    {
        var bufferSegment = new ArraySegment<byte>(_buffer);

        var receiveResult = await ReceiveAsync(ws, bufferSegment);
        if (receiveResult.MessageType == WebSocketMessageType.Text)
        {
          
                var message = Encoding.UTF8.GetString(bufferSegment.Array!, bufferSegment.Offset, receiveResult.Count);

                var note = serializer.Serialize(message);
                 

                await ws.SendAsync(new ArraySegment<byte>(Encoding.UTF8.GetBytes(message)), WebSocketMessageType.Text, true,
                CancellationToken.None);
        }

        while (!receiveResult.CloseStatus.HasValue)
        {
            await ws.SendAsync(
                new ArraySegment<byte>(_buffer, 0, receiveResult.Count),
                receiveResult.MessageType,
                receiveResult.EndOfMessage,
                CancellationToken.None);

            receiveResult = await ReceiveAsync(ws, bufferSegment);
        }

        await ws.CloseAsync(
            receiveResult.CloseStatus.Value,
            receiveResult.CloseStatusDescription,
            CancellationToken.None);
    }

    private async Task<WebSocketReceiveResult> ReceiveAsync(WebSocket ws, ArraySegment<byte> bufferSegment)
    {
        return await ws.ReceiveAsync(bufferSegment, CancellationToken.None);
    }
}