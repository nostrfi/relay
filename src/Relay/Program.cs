using Microsoft.AspNetCore.WebSockets;
using Nostrfi.Core.Connectivity;
using Nostrfi.Core.Events;
using Nostrfi.Core.Extensions;
using Nostrfi.Core.Handlers;
using Nostrfi.Core.Interfaces.Connectivity;
using Nostrfi.Core.Interfaces.Events;
using Nostrfi.Core.Interfaces.Handlers;
using Nostrfi.Persistence;
using Serilog;

var builder = WebApplication.CreateBuilder(args);
builder.Host.UseSerilog((ctx, lc) => lc.ReadFrom.Configuration(ctx.Configuration));
builder.Services.AddWebSockets(options =>
{
    options.KeepAliveInterval = TimeSpan.FromSeconds(120);
    options.KeepAliveTimeout = TimeSpan.FromSeconds(60);
});

builder.Services.AddNostrDatabase(builder.Configuration);
builder.Services.AddSingleton<IEventSerializer, EventSerializer>();
builder.Services.AddSingleton<IStateManager, ConnectionStateManager>();
builder.Services.AddSingleton<IWebsocketHandler, WebSocketHandler>();

var app = builder.Build();
app.UseRouting();
app.UseNostrDatabase();
app.UseWebSockets();
app.UseWebSocketMiddleware();
app.UseRestMiddleware();
app.Run();