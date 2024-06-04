using Nostrfi.Core;
using Nostrfi.Relay.Persistence;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddNostrDatabase(builder.Configuration);
builder.Services.AddControllers();
builder.Services.AddSingleton<SocketHandler>();
var app = builder.Build();

app.UseNostrDatabase();
app.UseWebSockets();
app.MapControllers();
app.Run();
