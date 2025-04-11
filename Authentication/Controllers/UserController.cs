using Authentication.Model;
using Authentication.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http;

namespace Authentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IUserService userService;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public UserController(IUserService userService, IHttpContextAccessor _httpContextAccessor)
        {
            this.userService = userService;
            this._httpContextAccessor  = _httpContextAccessor;
        }

        [HttpPost]
        public async Task<IActionResult> RegisterUser(RegisterUser user)
        {
            var result = await userService.RegisterAsync(user);
            return Ok(result);
        }


        [HttpPost("token")]
        public async Task<IActionResult> GetToken(TokenRequestModel model)
        {
            var result = await userService.GetTokenAsync(model);
            SetRefreshTokenInCookie(result.RefreshToken);
            return Ok(result);
        }

        //saving refrestoken as cookie
        private void SetRefreshTokenInCookie(string refreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddDays(10),
                Secure = true,
                SameSite = SameSiteMode.Strict
            };
            _httpContextAccessor.HttpContext!.Response.Cookies.Append("refreshToken", refreshToken, cookieOptions);
        }

        [HttpPost("addrole")]
        public async Task<IActionResult> GetToken(AddRoleModel model)
        {
            var result = await userService.AddRoleAsync(model);
            return Ok(result);
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            var response = await userService.RefreshTokenAsync(refreshToken!);
            if (!string.IsNullOrEmpty(response.RefreshToken))
                SetRefreshTokenInCookie(response.RefreshToken);
            return Ok(response);
        }

        [HttpPost("revoke-token")]
        public async Task<IActionResult> RevokeToken([FromBody] RevokeTokenRequest model)
        {
            // accept token from request body or cookie
            var token = model.Token ?? Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(token))
                return BadRequest(new { message = "Token is required" });

            var response = userService.RevokeToken(token);

            if (!response)
                return NotFound(new { message = "Token not found" });

            return Ok(new { message = "Token revoked" });
        }

    }
}
