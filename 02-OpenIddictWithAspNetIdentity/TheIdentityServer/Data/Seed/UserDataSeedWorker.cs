
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using System.Security.Claims;

namespace TheIdentityServer.Data.Seed
{
    public class UserDataSeedWorker : IHostedService
    {
        private readonly IServiceProvider serviceProvider;
        private readonly ILogger<UserDataSeedWorker> logger;

        public UserDataSeedWorker(IServiceProvider serviceProvider, ILogger<UserDataSeedWorker> logger)
        {
            this.serviceProvider = serviceProvider;
            this.logger = logger;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            await using (var scope = serviceProvider.CreateAsyncScope())
            {
                var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                await context.Database.EnsureCreatedAsync();

                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
                var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

                await SeedRoleOfSystemAdminAsync(roleManager);
                await SeedRoleOfBasicUserAsync(roleManager);
                await SeedUserAsync(userManager);
            }
            
        }

        public async Task StopAsync(CancellationToken cancellationToken)
        {
            await Task.CompletedTask;
        }

        private async Task SeedUserAsync(UserManager<IdentityUser> userManager)
        {
            var sysUser = new IdentityUser
            {
                Email = "neutrofoton@gmail.com",
                UserName = "neutrofoton@gmail.com",
                EmailConfirmed = true
            };

            var existingUserInDBWithTheSameEmail = await userManager.FindByEmailAsync(sysUser.Email);
            if (existingUserInDBWithTheSameEmail == null)
            {
                var identityResultUserCreation = await userManager.CreateAsync(sysUser, Constant.DefaultPassword);
                if (!identityResultUserCreation.Succeeded)
                {
                    foreach (var error in identityResultUserCreation.Errors)
                    {
                        logger.LogError($"{error.Code} - {error.Description}");
                    }
                }

                var identityResultUserRoleAssignment = await userManager.AddToRolesAsync(sysUser, new string[] { ConstantRole.SystemAdmin, ConstantRole.TenantAdmin });
                if (identityResultUserRoleAssignment.Succeeded)
                {
                    logger.LogInformation($"Seed user {sysUser.UserName} is success");
                }
            }
        }

        private static async Task SeedRoleOfSystemAdminAsync(RoleManager<IdentityRole> roleManager)
        {
            await SeedRoleAndPermissionAsync(roleManager, ConstantRole.SystemAdmin,
                new List<string>()
            {
                ConstantPermission.Create,
                ConstantPermission.View,
                ConstantPermission.Edit,
                ConstantPermission.Delete
            });

           
        }
        private static async Task SeedRoleOfBasicUserAsync(RoleManager<IdentityRole> roleManager)
        {
            await SeedRoleAndPermissionAsync(roleManager, ConstantRole.TenantAdmin,
                new List<string>()
            {
                ConstantPermission.Create,
                ConstantPermission.View,
                ConstantPermission.Edit
            });
        }
        private static async Task SeedRoleAndPermissionAsync(RoleManager<IdentityRole> roleManager, string roleName, IEnumerable<string> permissions)
        {
            var role = await roleManager.FindByNameAsync(roleName);
            if (role == null)
            {
                role = new IdentityRole()
                {
                    Name = roleName
                };
                await roleManager.CreateAsync(role);
            }

            var claims = await roleManager.GetClaimsAsync(role);
           

            foreach (var perm in permissions)
            {
                if (!claims.Any(a => a.Type == "Permission" && a.Value == perm))
                {
                    await roleManager.AddClaimAsync(role, new Claim("Permission", perm));
                }
            }
        }



    }
}
