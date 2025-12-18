using EImzoMVC;
using EImzoMVC.Models;
using EImzoMVC.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

builder.Services.AddScoped<ISignatureService, SignatureService>();

// Configure EImzo remote settings
builder.Services.Configure<EImzoConfig>(builder.Configuration.GetSection("EImzoConfig"));
var eImzoConfig = builder.Configuration.GetSection("EImzoConfig").Get<EImzoConfig>() ?? new EImzoConfig();
builder.Services.AddSingleton(eImzoConfig);

// HttpClient for EImzo remote API
builder.Services.AddHttpClient("EImzoClient", client =>
{
    client.Timeout = TimeSpan.FromSeconds(30);
});

builder.Services.AddSingleton<EImzoService>();

builder.Services
    .AddControllersWithViews()
    .AddNewtonsoftJson();


var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthorization();
app.UseSession();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Signature}/{action=Index}/{id?}");

app.Run();
