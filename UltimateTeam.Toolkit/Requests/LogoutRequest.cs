using System.Threading.Tasks;

namespace UltimateTeam.Toolkit.Requests
{
    internal class LogoutRequest : FutRequestBase, IFutRequest<bool>
    {
        public async Task<bool> PerformRequestAsync()
        {
            var uriString = "https://utas.external.s2.fut.ea.com/ut/auth";
            try
            {
                var response = await HttpClient.DeleteAsync(uriString);
            }
            catch
            {

            }

            return true;
        }
    }
}
