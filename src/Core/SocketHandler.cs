using System.Net.WebSockets;

namespace Nostrfi.Core;

public class SocketHandler
{
   public async Task Handle(WebSocket ws)
   {
      var buffer = new byte[1024 * 4];
      var receiveResult = await ws.ReceiveAsync(
         new ArraySegment<byte>(buffer), CancellationToken.None);

      while (!receiveResult.CloseStatus.HasValue)
      {
         await ws.SendAsync(
            new ArraySegment<byte>(buffer, 0, receiveResult.Count),
            receiveResult.MessageType,
            receiveResult.EndOfMessage,
            CancellationToken.None);

         receiveResult = await ws.ReceiveAsync(
            new ArraySegment<byte>(buffer), CancellationToken.None);
      }

      await ws.CloseAsync(
         receiveResult.CloseStatus.Value,
         receiveResult.CloseStatusDescription,
         CancellationToken.None);  
   }
}