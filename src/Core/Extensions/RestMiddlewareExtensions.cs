using Microsoft.AspNetCore.Builder;
using Nostrfi.Core.Middleware;

namespace Nostrfi.Core.Extensions;

public static class RestMiddlewareExtensions
{
    public static IApplicationBuilder UseRestMiddleware(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<RestMiddleware>();
    }
}