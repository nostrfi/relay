using Serilog;

namespace Nostrfi.Core.Interfaces.Handlers;

public interface IMessageHandler
{
    ILogger Logger { get; }
    Task HandleAsync(string connection, string message, CancellationToken cancellationToken);
}