using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Nostrfi.Core.Extensions;
using Nostrfi.Core.Interfaces.Connectivity;
using Nostrfi.Models;

namespace Nostrfi.Core.Connectivity;

public class ConnectionStateManager(ILogger<ConnectionStateManager> logger) : IStateManager
{
    private readonly ConcurrentDictionary<string, Channel<string>> _pendingMessages = new();
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _connectionChannels = new();

    public ConcurrentDictionary<string, WebSocket> Connections => new();

    private static readonly MultiConcurrentDictionary<string, string> ConnectionToSubscriptions =
        new();

    private readonly MultiConcurrentDictionary<string, SubscriptionFilter[]> _subscriptionFilters =
        new();
        
    public  void Add(string connection, WebSocket socket)
    {
        if (!Connections.TryAdd(connection, socket)) return;
        var cts = new CancellationTokenSource();
          
        var channel = _pendingMessages.GetOrAdd(connection, Channel.CreateUnbounded<string>());

        if (!_connectionChannels.TryAdd(connection, cts)) return;
        logger.LogTrace("Connection added to {ChannelName}", channel.GetType() );
        _ = Process(connection, channel, cts.Token);
    }
    public async Task Remove(string connection)
    {
        if (ConnectionToSubscriptions.Remove(connection, out var subscriptions))
        {
            foreach (var subscription in subscriptions)
            {
                _subscriptionFilters.Remove($"{connection}-{subscription}");
            }
        }

        if (_pendingMessages.Remove(connection, out var channel))
        {
            channel.Writer.TryComplete();
        }
        if (_connectionChannels.Remove(connection, out var cts))
        {
            await cts.CancelAsync();
        }
    }

    public string Get(WebSocket ws)
    {
        return Connections.FirstOrDefault(p => p.Value.Equals(ws)).Key.ToString();
    }

    private async Task Process(string connection, Channel<string> channel, CancellationToken cancellationToken)
    {
       
            while (await channel.Reader.WaitToReadAsync(cancellationToken))
            {
                if(!channel.Reader.TryRead(out var message)) continue;
                try
                {
                    if (Connections.TryRemove(connection, out var conn))
                    {
                        logger.LogTrace("Connection removed from {ChannelName}", channel.GetType());
                        await conn.SendMessageAsync(message, cancellationToken);
                    }

                    logger.LogWarning("Connection no longer exists for message {Message} ", message);
                }
                catch when (cancellationToken.IsCancellationRequested)
                {
                    
                }
                catch (Exception e)
                {
                   logger.LogError(e, "Error while processing message {Message}", message);
                }
              
            }
       
       
    }

    private async Task SendMessageLoggingErrors(string connectionId, string message, CancellationToken cancellationToken)
    {
        try
        {
            if (Connections.TryGetValue(connectionId, out var conn))
            {
                logger.LogTrace("sending message to connection {ConnectionId}\\n{Message}", connectionId, message);
                await conn.SendMessageAsync(message, cancellationToken);
            }
            else
            {
                logger.LogWarning("connection no longer exists for: {Message}", message);
            }
        }
        catch when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Unhandled exception in {Name}", this.GetType().Name);
        }
    }
    
    
}