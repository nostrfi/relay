using Microsoft.AspNetCore.Builder;
using Nostrfi.Core.Middleware;

namespace Nostrfi.Core.Extensions;

public static class WebSocketMiddlewareExtensions
{
    public static IApplicationBuilder UseWebSocketMiddleware(
        this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<WebSocketMiddleware>();
    }
}