using Microsoft.Extensions.Hosting;

namespace Nostrfi.Core.Handlers;

public class NostrEventHandler : BaseMessageHandler, IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}