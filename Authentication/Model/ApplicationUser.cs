using Authentication.Entity;
using Microsoft.AspNetCore.Identity;

namespace Authentication.Model
{
    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; } = string.Empty;

        public string LastName { get; set; } = string.Empty;

        public List<RefreshToken> RefreshTokens { get; set; }

    }
}
