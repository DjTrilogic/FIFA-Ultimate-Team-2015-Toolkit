using System.Threading.Tasks;

namespace UltimateTeam.Toolkit.Requests
{
    internal class LogoutRequest : FutRequestBase, IFutRequest<bool>
    {
        public async Task<bool> PerformRequestAsync()
        {
            var uriString = "https://utas.external.s2.fut.ea.com/ut/auth";

            var response = await HttpClient.DeleteAsync(uriString);

            return true;
        }
    }
}
