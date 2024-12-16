using Nostrfi.Relay.Integration.Tests.Fixtures;

namespace Nostrfi.Relay.Integration.Tests.Collections;

[CollectionDefinition(nameof(PostgreCollection))]
public class PostgreCollection : ICollectionFixture<PostgreSqlContainerFixture>;