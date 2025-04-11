using Authentication.Model;

namespace Authentication.Services
{
    public interface IUserService
    {
        Task<string> RegisterAsync(RegisterUser registerUser);

        Task<AuthenticationModel> GetTokenAsync(TokenRequestModel model);

        Task<string> AddRoleAsync(AddRoleModel modele);

        Task<AuthenticationModel> RefreshTokenAsync(string token);

        bool RevokeToken(string token);
    }
}
