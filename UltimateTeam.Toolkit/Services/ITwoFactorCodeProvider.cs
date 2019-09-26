using System.Threading.Tasks;
using UltimateTeam.Toolkit.Constants;

namespace UltimateTeam.Toolkit.Services
{
    public interface ITwoFactorCodeProvider
    {
        AuthenticationType HandledAuthType { get;}
        Task<string> GetTwoFactorCodeAsync(AuthenticationType authType);
    }
}
