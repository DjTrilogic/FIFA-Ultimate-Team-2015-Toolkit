﻿using System;
using System.Threading.Tasks;
using UltimateTeam.Toolkit.Constants;
using UltimateTeam.Toolkit.Extensions;
using UltimateTeam.Toolkit.Models;

namespace UltimateTeam.Toolkit.Requests
{
    internal class PileSizeRequest : FutRequestBase, IFutRequest<PileSizeResponse>
    {
        public async Task<PileSizeResponse> PerformRequestAsync()
        {
            var uriString = Resources.FutHome + Resources.PileSize;

            AddCommonHeaders();
            uriString += $"?_={DateTime.Now.ToUnixTime()}";

            var creditsResponseMessage = await HttpClient
                                                   .GetAsync(uriString)
                                                   .ConfigureAwait(false);

            return await DeserializeAsync<PileSizeResponse>(creditsResponseMessage).ConfigureAwait(false);
        }
    }
}