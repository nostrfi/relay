using System.Net.Mime;
using Microsoft.AspNetCore.Http;

namespace Nostrfi.Core.Middleware;

public class RestMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context)
    {
        if(!context.WebSockets.IsWebSocketRequest && context.Request.Headers.ContentType.Any(t => t.Equals(MediaTypeNames.Application.Json)))    
        
            await next(context);
    }
}

