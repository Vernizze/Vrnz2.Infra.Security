using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using Vrnz2.Infra.AsymmetricKeyHelper;
using Vrnz2.Infra.CrossCutting.Extensions;
using Vrnz2.Infra.Security.AppSettings;

namespace Vrnz2.Infra.Security.Types
{
    public struct JwtToken
    {
        #region Constants

        public const string JwtSubClaimName = "Sub";
        public const string FilePathClaimName = "filePath";
        public const string PwdClaimName = "pwd";
        public const string ExtraDataClaimName = "ex_data";

        #endregion

        #region Atributes

        public string OriginalValue { get; private set; }

        public string Value { get; private set; }

        public bool IsValid { get; private set; }

        public bool IsJwtToken { get; private set; }

        public DateTimeOffset? ExpirationDate { get; private set; }

        #endregion

        #region Constructors

        public JwtToken((StringDictionary ClaimsData, object AdditionaData) tokenData)
            : this()
            => IsValid = JwtIsValid(CreateToken(tokenData.ClaimsData, tokenData.AdditionaData));

        public JwtToken((CertificateConfig CertificateConfig, StringDictionary ClaimsData, object AdditionaData) tokenData)
            : this()
            => IsValid = JwtIsValid(CreateToken(tokenData.CertificateConfig, tokenData.ClaimsData, tokenData.AdditionaData));

        public JwtToken(string token)
            : this()
            => IsValid = JwtIsValid(token);

        #endregion

        #region Operator

        public static implicit operator JwtToken((CertificateConfig CertificateConfig, StringDictionary ClaimsData, object AdditionaData) tokenData)
            => new JwtToken(tokenData);

        public static implicit operator JwtToken((StringDictionary ClaimsData, object AdditionaData) tokenData)
            => new JwtToken(tokenData);

        #endregion

        #region Methods

        public bool IsEmpty()
            => string.IsNullOrWhiteSpace(Value);

        public bool IsNull()
            => Value.IsNull();

        #endregion

        #region methods

        public T GetClaimValue<T>(string claimName) 
        {
            if (!IsValid)
                return default(T);

            var claimValue = new JwtSecurityTokenHandler()
                .ReadJwtToken(OriginalValue)
                .Claims
                .FirstOrDefault(c => c.Type.Equals(claimName))?
                .Value;

            if (string.IsNullOrWhiteSpace(claimValue))
                return default;
            else
                return JsonConvert.DeserializeObject<T>(claimName);
        }

        private string CreateToken(CertificateConfig certificateConfig, StringDictionary claimsData, object data)
        {
            using (var asym_key = new AsymmetricKey(certificateConfig))
                return CreateToken(asym_key, claimsData, data);
        }

        private string CreateToken(StringDictionary claimsData, object data)
        {
            using var asym_key = new AsymmetricKey(claimsData[FilePathClaimName], claimsData[PwdClaimName]);
            return CreateToken(asym_key, claimsData, data);
        }

        private string CreateToken(AsymmetricKey asymmetricKey, StringDictionary claimsData, object data)
        {            
            var tokenHandler = new JwtSecurityTokenHandler();

            if (data.IsNotNull())
                claimsData.Add(ExtraDataClaimName, asymmetricKey.Encrypt(data.ToJson()));

            var token = tokenHandler.CreateToken(new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(GetClaims(claimsData)),
                Issuer = SecurityAppSettingsHandler.Instance.SecurityAppSettings.TokenIssuer,
                Audience = SecurityAppSettingsHandler.Instance.SecurityAppSettings.TokenAudience,
                SigningCredentials = SecurityAppSettingsHandler.Instance.SecurityAppSettings.SigningCredentials,
                IssuedAt = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddMinutes(SecurityAppSettingsHandler.Instance.SecurityAppSettings.TokenLifetimeInMinutes)
            });

            return tokenHandler.WriteToken(token);
        }

        private List<Claim> GetClaims(StringDictionary claimsData) 
        {
            var result = new List<Claim> { new Claim(JwtRegisteredClaimNames.Sub, claimsData[JwtSubClaimName]) };

            foreach (KeyValuePair<string, string> claimData in claimsData)
                result.Add(new Claim(claimData.Key, claimData.Value));

            return result;
        }

        private bool JwtIsValid(string token)
        {
            OriginalValue = token;

            var jwtToken = new JwtSecurityTokenHandler().ReadJwtToken(OriginalValue);

            IsJwtToken = jwtToken.IsNotNull();

            IsValid = IsJwtToken && jwtToken.ValidFrom <= DateTimeOffset.UtcNow && DateTimeOffset.UtcNow <= jwtToken.ValidTo;

            if (!IsValid) ExpirationDate = jwtToken?.ValidTo;

            if (IsValid) Value = OriginalValue;

            return IsValid;
        }

        #endregion
    }
}
