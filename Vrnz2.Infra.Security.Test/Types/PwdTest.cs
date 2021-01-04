using Vrnz2.Infra.Security.Types;
using Xunit;

namespace Vrnz2.Infra.Security.Test.Types
{
    public class PwdTest
    {
        [Theory]
        [InlineData("#123Abcd")]
        public void ValidPwd_StringValue_Valid(string value)
        {
            Pwd pwd = value;

            Assert.True(pwd.IsValid);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("@1A")]
        [InlineData("2123Abcd")]
        [InlineData("#123A cd")]
        [InlineData("#adadAbcd")]
        [InlineData("#123abcd")]
        public void ValidPwd_StringValue_NotValid(string value)
        {
            Pwd pwd = value;

            Assert.False(pwd.IsValid);
        }

        [Theory]
        [InlineData("#123Abcd", "#123Abcd")]
        public void ValidPwd_Compare_Success(string value01, string value02)
        {
            Pwd pwd01 = value01;
            Pwd pwd02 = value02;

            Assert.NotEqual(pwd01.Value, pwd02.Value);
        }
    }
}
