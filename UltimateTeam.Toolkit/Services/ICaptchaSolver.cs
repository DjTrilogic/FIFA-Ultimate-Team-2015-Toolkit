using System.Net;
using System.Threading.Tasks;
using UltimateTeam.Toolkit.Models;

namespace UltimateTeam.Toolkit.Services
{
    public interface ICaptchaSolver
    {
        bool UseSameProxy { get; }
        bool IsEnabled { get; }

        Task<CaptchaValidationRequest> Solve(IWebProxy webProxy);

        Task<CaptchaValidationRequest> Solve();
    }
}