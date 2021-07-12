using Microsoft.IdentityModel.Tokens;
using System.Text;
using Vrnz2.Infra.CrossCutting.Utils;

namespace Vrnz2.Infra.Security.AppSettings
{
    public class SecurityAppSettingsHandler
    {
        private static SecurityAppSettingsHandler _instance;

        private SecurityAppSettingsHandler() 
        {
            SecurityAppSettings = FilesAndFolders.GetAppSettingsContent<SecurityAppSettings>();

            SecurityAppSettings.SecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecurityAppSettings.SigningKey));

            SecurityAppSettings.SigningCredentials = new SigningCredentials(SecurityAppSettings.SecurityKey, SecurityAlgorithms.HmacSha256);
        }

        public static SecurityAppSettingsHandler Instance 
        {
            get 
            {
                _instance ??= new SecurityAppSettingsHandler();

                return _instance;
            }
        }

        public SecurityAppSettings SecurityAppSettings { private set; get; }
    }
}
