using Microsoft.Extensions.Hosting;
using Serilog;
using Serilog.Events;

namespace Vault.Cli;

public static class Startup
{
    public static IHost ConfigureHost(this HostApplicationBuilder builder)
    {
        builder.AddLogging();

        return builder.Build();
    }

    private static void AddLogging(this HostApplicationBuilder builder)
    {
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Debug()
            .Enrich.FromLogContext()
            .WriteTo.Console(
                LogEventLevel.Debug,
                "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message:lj}{NewLine}{Exception}{NewLine}")
            .CreateLogger();

        builder.Services.AddSerilog();
    }
}
