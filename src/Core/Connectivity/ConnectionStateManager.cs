using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Threading.Channels;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using Nostrfi.Core.Extensions;
using Nostrfi.Models;

namespace Nostrfi.Core;

public class ConnectionStateManager(ILogger<ConnectionStateManager> logger)
{
    private readonly ConcurrentDictionary<string, Channel<string>> _pendingMessages = new();
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _connectionChannels = new();

    public static ConcurrentDictionary<string, WebSocket> Connections => new();
    public static MultiConcurrentDictionary<string, string> DictionaryToSubscriptions =
        new();
    public readonly MultiConcurrentDictionary<string, SubscriptionFilter[]> ConnectionSubscriptionsToFilters =
        new();

    
    public void Add(string connectionId)
    {
        var cts = new CancellationTokenSource();
        var channel = _pendingMessages.GetOrAdd(connectionId, Channel.CreateUnbounded<string>());
        if (_connectionChannels.TryAdd(connectionId, cts))
        {
            _ = Process(connectionId, channel, cts.Token);
            /*
             * The _ = before the asynchronous method call Process denotes that the code does not
             * require the use of the task result. This is a common practice when the result of the Task is not needed, and it makes the code cleaner by indicating that the returned Task is purposely being ignored.
             */
        }
    }
    public void Remove(string connectionId)
    {
        if (DictionaryToSubscriptions.Remove(connectionId, out var subscriptions))
        {
            foreach (var subscription in subscriptions)
            {
                ConnectionSubscriptionsToFilters.Remove($"{connectionId}-{subscription}");
            }
        }

        if (_pendingMessages.Remove(connectionId, out var channel))
        {
            channel.Writer.TryComplete();
        }
        if (_connectionChannels.Remove(connectionId, out var cts))
        {
            cts.Cancel();
        }
    }
    
    private async Task Process(string connectionId, Channel<string> channel, CancellationToken cancellationToken)
    {
        while (await channel.Reader.WaitToReadAsync(cancellationToken))
        {
            if (channel.Reader.TryRead(out var message))
            {
                await SendMessageLoggingErrors(connectionId, message, cancellationToken);
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