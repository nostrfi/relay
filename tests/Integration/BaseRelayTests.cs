using Microsoft.EntityFrameworkCore;
using Nostrfi.Persistence;
using Nostrfi.Relay.Integration.Tests.Collections;
using Nostrfi.Relay.Integration.Tests.Fixtures;

namespace Nostrfi.Relay.Integration.Tests;

[Collection(nameof(PostgreCollection))]
public abstract class BaseRelayTests(PostgreSqlContainerFixture fixture) : IAsyncLifetime
{
    protected NostrContext Context { get; set; } = null!;


    public async Task InitializeAsync()
    {
        await fixture.InitializeAsync();
        var options = new DbContextOptionsBuilder<NostrContext>()
            .UseNpgsql(fixture.ConnectionString)
            .Options;

        Context = new NostrContext(options);
    }

    public async Task DisposeAsync()
    {
        await Context.DisposeAsync();
    }
}