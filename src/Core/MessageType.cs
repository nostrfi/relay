using System.ComponentModel;

namespace Nostrfi.Core;

public static class MessageType
{
    [Description("used to publish events or notify clients all stored events have been sent")]
    public static string Event => "EVENT";
    
    [Description("used to request events and subscribe to new updates")]
    public static string Req => "REQ";
    
    [Description("used to stop previous subscriptions ")]
    public static string Close => "CLOSE";
    
    [Description("used to send authentication events or challenges")]
    public static string Auth => "AUTH";
    
    [Description("used to request event counts")]
    public static string Count => "Count";

    [Description("used to notify clients all stored events have been sent")]
    public static string Eose => "EOSE";

    [Description("used to send human-readable messages to clients")]
    public static string Notice => "NOTICE";

    [Description("used to notify clients that a REQ was ended and why")]
    public static string Closed => "CLOSED";

    [Description("used to notify clients if an EVENT was successful ")]
    public static string Ok => "OK";



}