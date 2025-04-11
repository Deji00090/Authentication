using Newtonsoft.Json;

namespace Authentication.Model
{
    
        public class AuthenticationModel
        {
            public string Message { get; set; } = string.Empty;
            public bool IsAuthenticated { get; set; }
            public string UserName { get; set; } = string.Empty;
            public string Email { get; set; } = string.Empty;
            public  List<string> Roles { get; set; } 
            public string Token { get; set; } = string.Empty;

        //refersh token info
        [JsonIgnore]
         public string RefreshToken { get; set; } = string.Empty;

         public DateTime RefreshTokenExpiration { get; set; }
        
    }
}
