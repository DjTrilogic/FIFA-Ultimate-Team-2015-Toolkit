using System;
using System.Threading.Tasks;
using UltimateTeam.Toolkit.Constants;
using UltimateTeam.Toolkit.Extensions;
using UltimateTeam.Toolkit.Models;

namespace UltimateTeam.Toolkit.Requests
{
    internal class ConsumablesRequest : FutRequestBase, IFutRequest<ConsumablesResponse>
    {
        public async Task<ConsumablesResponse> PerformRequestAsync()
        {
            var uriString = Resources.FutHome + Resources.Consumables;
            AddCommonHeaders();
            uriString += $"?_={DateTime.Now.ToUnixTime()}";

            var consumablesResponseMessage = await HttpClient
                .GetAsync(string.Format(uriString))
                .ConfigureAwait(false);

            return await DeserializeAsync<ConsumablesResponse>(consumablesResponseMessage)
                .ConfigureAwait(false);
        }
    }
}
