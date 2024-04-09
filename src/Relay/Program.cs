using Nostrfi.Relay.Persistence;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddNostrDatabase(builder.Configuration);

var app = builder.Build();

app.UseNostrDatabase();
app.UseWebSockets();

app.Run();
