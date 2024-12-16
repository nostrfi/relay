namespace Nostrfi.Core.Interfaces.Handlers;

public interface IMessageHandler
{
    Task HandleAsync(string connection, string message, CancellationToken cancellationToken);
}