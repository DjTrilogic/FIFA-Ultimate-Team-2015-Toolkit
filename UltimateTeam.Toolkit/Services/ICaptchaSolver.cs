using System.Threading.Tasks;
using UltimateTeam.Toolkit.Models;
using UltimateTeam.Toolkit.Requests;

namespace UltimateTeam.Toolkit.Services
{
    public delegate void CaptchaDelegate(LoginDetails loginDetails, bool success, string errorMessage);

    public interface ICaptchaSolver
    {
        bool UseSameProxy { get; }
        bool IsEnabled { get; }

        Task<CaptchaValidationRequest> Solve(LoginRequest loginRequest);

        event CaptchaDelegate OnCaptchaHandled;
    }
}