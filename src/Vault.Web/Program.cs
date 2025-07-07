using Vault.Web;

var app = WebApplication.CreateBuilder(args)
    .ConfigureServices()
    .ConfigurePipeline();

app.Run();