using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.SqlServer;
using ExtendEFIdentity.Entities;
using Microsoft.AspNetCore.Http;
using System.Diagnostics;

namespace ExtendEFIdentity
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            string assemblyName = typeof(Startup).Assembly.GetName().Name;
            services.AddLogging();
            services.AddDbContext<AppDbContext>(options =>
            {
                options.UseSqlServer(Configuration.GetConnectionString("SqlServer"), sqlOptions =>
                {
                    sqlOptions.MigrationsAssembly(assemblyName);
                });
            });
            services.AddIdentity<AppUser, IdentityRole>(options =>
            {

                //for demo purpose, i deactivate these password options
                options.Password.RequireDigit = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireUppercase = false;
                options.Password.RequiredLength = 5;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequiredUniqueChars = 0;

                //this to prevent duplicated email/username
                options.User.RequireUniqueEmail = true;

                //these to prevent continuously failed login attempt
                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);
                options.Lockout.MaxFailedAccessAttempts = 3;


            })
                .AddDefaultTokenProviders()
                .AddEntityFrameworkStores<AppDbContext>(); //this is required!

            services.AddAuthorization(options =>
            {
                options.AddPolicy("ReaderPolicy", o =>
                {
                    o.RequireAuthenticatedUser();
                    o.RequireClaim("type", "READER");
                });
            });
            services.ConfigureApplicationCookie(options =>
            {
                options.LoginPath = new PathString("/auth/login");
                options.LogoutPath = new PathString("/auth/logout");
                options.AccessDeniedPath = new PathString("/auth/accessdenied");
            });

            services.AddAuthentication()
                .AddGoogle(AppConstants.GoogleAuthenticationScheme, options =>
                {
                    options.ClientId = Configuration["GoogleCredentials:ClientId"];
                    options.ClientSecret = Configuration["GoogleCredentials:ClientSecret"];
                    options.SaveTokens = true;
                    options.SignInScheme = IdentityConstants.ExternalScheme;
                });

            services.AddControllersWithViews()
                .AddRazorRuntimeCompilation();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            InitAdminUserAndRole(userManager, roleManager);
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }

        private void InitAdminUserAndRole(UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            bool next = true;
            string adminRoleName = "ADMIN";
            string userName = "admin@demo.com";
            string fullName = "Administrator";
            string password = "future";
            try
            {
                IdentityRole role = new IdentityRole(adminRoleName);
                if (!roleManager.RoleExistsAsync(adminRoleName).Result)
                {
                    var createRoleResult = roleManager.CreateAsync(role).GetAwaiter().GetResult();
                    if (!createRoleResult.Succeeded)
                    {
                        next = false;
                    }
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine(ex);
                next = false;
            }
            if (next)
            {
                try
                {
                    if (userManager.FindByNameAsync(userName).Result == null)
                    {
                        var user = new AppUser
                        {
                            UserName = userName,
                            Email = userName,
                            EmailConfirmed = true,
                            FullName = fullName
                        };
                        var createAdminResult = userManager.CreateAsync(user, password).GetAwaiter().GetResult();
                        if (!createAdminResult.Succeeded)
                        {
                            next = false;
                        }
                        else
                        {
                            var addToRoleResult = userManager.AddToRoleAsync(user, adminRoleName).GetAwaiter().GetResult();
                            if (!addToRoleResult.Succeeded)
                            {
                                next = false;
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Trace.WriteLine(ex);
                    next = false;
                }
            }


            //consume your NEXT variable....
        }
    }
}
