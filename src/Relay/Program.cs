using Nostrfi.Core;
using Nostrfi.Core.Events;
using Nostrfi.Persistence;


var builder = WebApplication.CreateBuilder(args);

builder.Services.AddNostrDatabase(builder.Configuration);
builder.Services.AddControllers();
builder.Services.AddSingleton<IEventSerializer, EventSerializer>();
builder.Services.AddSingleton<WebSocketHandler>();
var app = builder.Build();

app.UseNostrDatabase();
app.UseWebSockets();
app.MapControllers();
app.Run();
