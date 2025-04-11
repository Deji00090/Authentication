using Authentication.Contacts;
using Authentication.Model;
using Microsoft.AspNetCore.Identity;

namespace Authentication.Data
{
    public class ApplicationDbContextSeeding
    {
        public static async Task SeedEssentialsAsync(UserManager<ApplicationUser> userManager,RoleManager<IdentityRole> roleManager)
        {
            //seed roles

            await roleManager.CreateAsync(new IdentityRole(Authorization.Roles.Admin.ToString()));
            await roleManager.CreateAsync(new IdentityRole(Authorization.Roles.Moderator.ToString()));
            await roleManager.CreateAsync(new IdentityRole(Authorization.Roles.User.ToString()));

            //seed default users
            var defaultUser = new ApplicationUser { UserName = Authorization.default_username, Email = Authorization.default_email, EmailConfirmed = true, PhoneNumberConfirmed = true };
        
            if(userManager.Users.All(u => u.Id != defaultUser.Id))
            {
                await userManager.CreateAsync(defaultUser,Authorization.default_password.ToString());
                await userManager.AddToRoleAsync(defaultUser, Authorization.default_role.ToString());
            }


        }
    }
}
