using Authentication.Contacts;
using Authentication.Data;
using Authentication.Model;
using Authentication.Services;
using Authentication.Settings;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;
using Serilog;
using System.Text;

var builder = WebApplication.CreateBuilder(args);


Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .WriteTo.File("Log/log.txt", rollingInterval: RollingInterval.Hour)
    .CreateLogger();
//builder.Services.Configure<JWT>(IConfiguration.GetSection("JWT"));


//builder.Services.Configure<JWT>(con)
builder.Services.Configure<JWT>(builder.Configuration.GetSection("JWT"));


//identity service
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>();

//Adding dbcontext with sqlserver...

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"),
   b => b.MigrationsAssembly(typeof(ApplicationDbContext).Assembly.FullName));
});

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(option =>
    {
        option.RequireHttpsMetadata = false;
        option.SaveToken = false;
        option.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            ValidateAudience = true,
            ValidateIssuer = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,

            ValidIssuer = builder.Configuration["JWT:Issuer"],
            ValidAudience = builder.Configuration["JWT:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Key"]!))
        };
    });

builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddHttpContextAccessor();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var loggerFactory = services.GetRequiredService<ILoggerFactory>();
    try
    {
        var usermanager = services.GetRequiredService<UserManager<ApplicationUser>>();
        var rolmanager = services.GetRequiredService<RoleManager<IdentityRole>>();
        await ApplicationDbContextSeeding.SeedEssentialsAsync(usermanager, rolmanager);
    }
    catch (Exception ex)
    {

        var logger = loggerFactory.CreateLogger<Program>();
            logger.LogError(ex, "An error occurred while seeding the DB");
    }


}

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();
