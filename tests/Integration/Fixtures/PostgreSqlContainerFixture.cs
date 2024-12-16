using Microsoft.EntityFrameworkCore;
using Nostrfi.Persistence;
using Testcontainers.PostgreSql;

namespace Nostrfi.Relay.Integration.Tests.Fixtures;

public class PostgreSqlContainerFixture
{
    private readonly PostgreSqlContainer _container = new PostgreSqlBuilder()
        .WithImage("postgres:15.1")
        .Build();

    public string ConnectionString => _container.GetConnectionString();
    public string ContainerId => _container.Id;

    public async Task InitializeAsync()
    {
        await _container.StartAsync();
        var options = new DbContextOptionsBuilder<NostrContext>()
            .UseNpgsql(_container.GetConnectionString())
            .Options;

        var context = new NostrContext(options);
        await context.Database.MigrateAsync();
    }

    public async Task DisposeAsync()
    {
        await _container.DisposeAsync();
    }
}