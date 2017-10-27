using System;
using System.Text;
using DualAuthCoreExample.Models;
using DualAuthCoreExample.Auth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using DualAuthCoreExample.Data;
using DualAuthCoreExample.Options;
using DualAuthCoreExample.Services;

namespace DualAuthCoreExample
{
    public static class IServiceCollectionExtensions
    {
        public static IServiceCollection AddAuthenticationProviders(this IServiceCollection services, IConfiguration configuration)
        {
            var signingKey = GetJwtSigningKey(configuration);
            var jwtAppSettingOptions = configuration.GetSection(nameof(JwtIssuerOptions));
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = jwtAppSettingOptions[nameof(JwtIssuerOptions.Issuer)],

                ValidateAudience = true,
                ValidAudience = jwtAppSettingOptions[nameof(JwtIssuerOptions.Audience)],

                ValidateIssuerSigningKey = true,
                IssuerSigningKey = signingKey,

                RequireExpirationTime = false,
                ValidateLifetime = false,
                ClockSkew = TimeSpan.Zero
            };

            services.AddAuthentication()
                .AddCookie(options =>
                {
                    options.LoginPath = new PathString("/Account/Login/");
                    options.AccessDeniedPath = new PathString("/Account/Forbidden/");
                    options.LogoutPath = new PathString("/Account/Logoff");
                    options.ExpireTimeSpan = TimeSpan.FromDays(Convert.ToInt32(configuration["Auth:ExpirationMinutes"]));
                })
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = tokenValidationParameters;
                });

            return services;
        }

        private static SymmetricSecurityKey GetJwtSigningKey(IConfiguration configuration)
        {
            var jwtSecretKey = configuration["Jwt:SecretKey"];
            var signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(jwtSecretKey));
            return signingKey;
        }

        public static IServiceCollection AddApplicationServices(this IServiceCollection services)
        {
            services.AddTransient<IEmailSender, EmailSender>();
            ////services.AddTransient<ISmsSender, AuthMessageSender>();
            services.AddSingleton<IJwtFactory, JwtFactory>();

            return services;
        }

        public static IServiceCollection AddApplicationOptions(this IServiceCollection services, IConfiguration configuration/*, IHostingEnvironment env*/)
        {
            // Setup options with DI
            services.AddOptions();

            ////services.Configure<CsOptions.Mail>(mailOptions =>
            ////{
            ////    mailOptions.SmtpServer = configuration["MailOptions:SmtpServer"];
            ////    mailOptions.SmtpServerUsername = env.IsDevelopment() ? "save.to.disk" : configuration["MailOptions:SmtpServerUsername"];
            ////    mailOptions.SmtpServerPassword = configuration["MailOptions:SmtpServerPassword"];
            ////    mailOptions.FromName = configuration["MailOptions:FromName"];
            ////    mailOptions.FromMail = configuration["MailOptions:FromMail"];
            ////});

            // Auth(z) options.
            services.Configure<AuthOptions>(configuration.GetSection("Auth"));
            services.Configure<VersionOptions>(configuration.GetSection("Version"));

            return services;
        }

        public static IServiceCollection AddJwtIssuerOptions(this IServiceCollection services, IConfiguration configuration)
        {
            var jwtAppSettingOptions = configuration.GetSection(nameof(JwtIssuerOptions));
            var signingKey = GetJwtSigningKey(configuration);

            // Configure JwtIssuerOptions
            services.Configure<JwtIssuerOptions>(options =>
            {
                options.Issuer = jwtAppSettingOptions[nameof(JwtIssuerOptions.Issuer)];
                options.Audience = jwtAppSettingOptions[nameof(JwtIssuerOptions.Audience)];
                options.SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);
            });

            return services;
        }

        public static IServiceCollection AddApplicationIdentity(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                // Password requirements.
                options.Password.RequireDigit = false;
                options.Password.RequiredLength = Convert.ToInt32(configuration["Auth:RequiredPasswordLength"]);
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = false;
                options.Password.RequireLowercase = false;

                // Lockout on repeated fails.
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(Convert.ToInt32(configuration["Auth:LockoutFor"]));
                options.Lockout.MaxFailedAccessAttempts = Convert.ToInt32(configuration["Auth:MaxFailedLoginAttempts"]);

                // User settings
                options.User.RequireUniqueEmail = true;

                options.SignIn.RequireConfirmedEmail = false; // For a production system this must be true.
            })
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            return services;
        }

        public static IServiceCollection AddApplicationAuthorization(this IServiceCollection services)
        {
            // api user claim policy
            services.AddAuthorization(options =>
            {
                options.AddPolicy("ApiUser", policy =>
                {
                    policy.RequireClaim(Helpers.Constants.Strings.JwtClaimIdentifiers.Rol, Helpers.Constants.Strings.JwtClaims.ApiAccess);
                });
            });

            return services;
        }
    }
}