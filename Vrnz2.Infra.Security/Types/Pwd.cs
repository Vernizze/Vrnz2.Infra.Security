using System.Linq;
using System.Text.RegularExpressions;
using Vrnz2.Infra.CrossCutting.Extensions;
using Vrnz2.Infra.Security.Libraries;

namespace Vrnz2.Infra.Security.Types
{
    public struct Pwd
    {
        #region Constants

        private const string SPECIAL_CHARS = @"\|!#$%&/()=?»«@£§€{}.-;'<>_,";

        #endregion 

        #region Atributes

        public readonly bool IsValid { get; }

        public readonly string Value { get; }

        #endregion

        #region Constructors

        public Pwd(string value)
            : this()
        {
            this.IsValid = Valid(value);

            if (this.IsValid)
                this.Value = PBKDF2.Compute(value);
        }

        #endregion

        #region Operators

        public static implicit operator Pwd(string value)
            => new Pwd(value);

        #endregion

        #region Methods

        #endregion

        #region Static methods

        public static bool Valid(string value)
            =>
                !string.IsNullOrEmpty(value) &&                                                 //Not Null or Empty
                (value.ToCharArray().Intersect(SPECIAL_CHARS.ToCharArray())).HaveAny() &&       //Must have Special Character
                new Regex(@"[0-9]+").IsMatch(value) &&                                          //Must have Number
                new Regex(@"[A-Z]+").IsMatch(value) &&                                          //Must have Upper Case Letter
                new Regex(@".{8,}").IsMatch(value) &&                                           //Must have eight characters 
                !(new Regex(@" ").IsMatch(value));                                              //Don't have white spaces

        #endregion        
    }
}
