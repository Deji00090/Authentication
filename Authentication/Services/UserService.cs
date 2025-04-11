using Authentication.Contacts;
using Authentication.Data;
using Authentication.Entity;
using Authentication.Model;
using Authentication.Settings;
using Azure;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Authentication.Services
{
    public class UserService:IUserService
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration configuration;
        private readonly JWT jwt;
        private readonly ApplicationDbContext context;
        public UserService(IOptions<JWT> jwt,
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager, 
            IConfiguration configuration,
            ApplicationDbContext context
            )
        {
            //
            this.userManager = userManager;
            this.roleManager = roleManager;
            this.configuration = configuration;
           this.jwt = jwt.Value;
            this.context = context;
        }

       
           public async Task<AuthenticationModel> GetTokenAsync(TokenRequestModel model)
        {
            
            var authenticationModel = new AuthenticationModel();
            var user = await userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                authenticationModel.IsAuthenticated = false;
                authenticationModel.Message = $"No Accounts Registered with {model.Email}.";
                return authenticationModel;
            }
            if (await userManager.CheckPasswordAsync(user, model.Password))
            {
                authenticationModel.IsAuthenticated = true;
                JwtSecurityToken jwtSecurityToken = await GenerateToken(user);
                authenticationModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
                authenticationModel.Email = user.Email!;
                authenticationModel.UserName = user.UserName!;
                var rolesList = await userManager.GetRolesAsync(user).ConfigureAwait(false);
                authenticationModel.Roles = rolesList.ToList();


                if (user.RefreshTokens.Any(a => a.IsActive))
                {
                    var activeRefreshToken = user.RefreshTokens.Where(a => a.IsActive == true).FirstOrDefault();
                    authenticationModel.RefreshToken = activeRefreshToken.Token;
                    authenticationModel.RefreshTokenExpiration = activeRefreshToken.Expires;
                }
                else
                {
                    var refreshToken = CreateRefreshToken();
                    authenticationModel.RefreshToken = refreshToken.Token;
                    authenticationModel.RefreshTokenExpiration = refreshToken.Expires;
                    user.RefreshTokens.Add(refreshToken);
                    context.Update(user);
                    context.SaveChanges();
                }


                return authenticationModel;
                Log.Error("accounts authed");
            }
            authenticationModel.IsAuthenticated = false;
            authenticationModel.Message = $"Incorrect Credentials for user {user.Email}.";
            return authenticationModel;
            Log.Error("incorrect credentials");
        }
            
        

        private async Task<JwtSecurityToken> GenerateToken(ApplicationUser user)
        {

            var userclaims = await userManager.GetClaimsAsync(user);
            var userroles = await userManager.GetRolesAsync(user);


            //role claims to get the claims of the user particular role
            var roleClaims = new List<Claim>();

            for(int i= 0; i< userroles.Count; i++)
            {
                roleClaims.Add(new Claim("role", userroles[i]));
            }

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub,user.UserName!),
                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email,user.Email!),
                new Claim("uid",user.Id)
            }
            //no multple claims for either roles or user
            .Union(userclaims)
            .Union(roleClaims);

            var symmetrykey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.Key));
            var signingcredentials = new SigningCredentials(symmetrykey, SecurityAlgorithms.HmacSha256);
            var jwttoken = new JwtSecurityToken(
                issuer: jwt.Issuer,
                audience: jwt.Audience,
                claims: claims,
                expires: DateTime.Now.AddMinutes(10),
                signingCredentials: signingcredentials
                );
            return jwttoken;
        }

        public async Task<string> RegisterAsync(RegisterUser myuser)
        {
            var newuser = new ApplicationUser
            {
                UserName = myuser.Username,
                FirstName = myuser.FirstName,
                LastName = myuser.LastName,
                Email = myuser.Email
            };

            //check user with same email

            var userwithsameemail =  await userManager.FindByEmailAsync(myuser.Email);
            if(userwithsameemail == null)
            {
                var result = await userManager.CreateAsync(newuser, myuser.Password);
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(newuser, Authorization.default_role.ToString())
;               }

                return $"User registered with {newuser.UserName}";
            }
            else
            {
                return $"Email {newuser.Email} is already registered.";
            }
        }

        public async Task<string> AddRoleAsync(AddRoleModel modele)
        {
            var user =  await userManager.FindByEmailAsync(modele.Email);
            if(user == null)
            {
                return $"User with{modele.Email} not found";
            }
            if(await userManager.CheckPasswordAsync(user, modele.Password))
            {
                // get the role entered
                var roleExists = Enum.GetNames(typeof(Authorization.Roles))
                    .Any(x => x.ToLower() == modele.Role.ToLower());

                //if row exists
                if (roleExists) {
                    var validrole = Enum.GetValues(typeof(Authorization.Roles))
                        .Cast<Authorization.Roles>()
                        .Where(x => x.ToString().ToLower() == modele.Role.ToLower()).FirstOrDefault();
                    
                    await userManager.AddToRoleAsync(user,validrole.ToString());
                    return $"Added {modele.Role} to user {modele.Email}  ";
                }
            }

            return "User Credentials incorrect";
        }

        private RefreshToken CreateRefreshToken()
        {
            var randomnumber = new byte[32];
            using(var generator = RandomNumberGenerator.Create())
            {
                generator.GetBytes(randomnumber);
                return new RefreshToken
                {
                    Token = Convert.ToBase64String(randomnumber),
                    Expires = DateTime.Now.AddDays(10),  
                    Created = DateTime.Now
                };
            }
        }

        public async Task<AuthenticationModel> RefreshTokenAsync(string token)
        {
            var authenticationModel = new AuthenticationModel();
            var user = context.Users.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));
            if (user == null)
            {
                authenticationModel.IsAuthenticated = false;
                authenticationModel.Message = $"Token did not match any users.";
                return authenticationModel;
            }

            var refreshToken = user.RefreshTokens.Single(x => x.Token == token);

            if (!refreshToken.IsActive)
            {
                authenticationModel.IsAuthenticated = false;
                authenticationModel.Message = $"Token Not Active.";
                return authenticationModel;
            }

            //Revoke Current Refresh Token
            refreshToken.Revoked = DateTime.UtcNow;

            //Generate new Refresh Token and save to Database
            var newRefreshToken = CreateRefreshToken();
            user.RefreshTokens.Add(newRefreshToken);
            context.Update(user);
            context.SaveChanges();

            //Generates new jwt
            authenticationModel.IsAuthenticated = true;
            JwtSecurityToken jwtSecurityToken = await GenerateToken(user);
            authenticationModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            authenticationModel.Email = user.Email!;
            authenticationModel.UserName = user.UserName!;
            var rolesList = await userManager.GetRolesAsync(user).ConfigureAwait(false);
            authenticationModel.Roles = rolesList.ToList();
            authenticationModel.RefreshToken = newRefreshToken.Token;
            authenticationModel.RefreshTokenExpiration = newRefreshToken.Expires;
            return authenticationModel;
        }

        public bool RevokeToken(string token)
        {
            var user = context.Users.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));

            // return false if no user found with token
            if (user == null) return false;

            var refreshToken = user.RefreshTokens.Single(x => x.Token == token);

            // return false if token is not active
            if (!refreshToken.IsActive) return false;

            // revoke token and save
            refreshToken.Revoked = DateTime.UtcNow;
            context.Update(user);
            context.SaveChanges();

            return true;
        }
    }
}
