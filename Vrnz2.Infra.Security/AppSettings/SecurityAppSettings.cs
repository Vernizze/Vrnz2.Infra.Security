using Microsoft.IdentityModel.Tokens;

namespace Vrnz2.Infra.Security.AppSettings
{
    public class SecurityAppSettings
    {
        public string SigningKey { get; set; }
        public string TokenIssuer { get; set; }
        public string TokenAudience { get; set; }
        public int TokenLifetimeInMinutes { get; set; }
        public SecurityKey SecurityKey { get; set; }
        public SigningCredentials SigningCredentials { get; set; }
    }
}
