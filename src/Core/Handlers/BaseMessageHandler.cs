using Nostrfi.Core.Interfaces.Handlers;
using Serilog;

namespace Nostrfi.Core.Handlers;

public abstract class BaseMessageHandler : IMessageHandler
{
 

    public ILogger Logger { get; }

    public virtual Task HandleAsync(string connection, string message, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}