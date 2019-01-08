﻿using System;
using System.Threading.Tasks;
using UltimateTeam.Toolkit.Constants;
using UltimateTeam.Toolkit.Extensions;
using UltimateTeam.Toolkit.Models;

namespace UltimateTeam.Toolkit.Requests
{
    internal class ClubItemRequest : FutRequestBase, IFutRequest<ClubItemResponse>
    {
        private readonly uint _listType;
        // _listType:
        //  1 = Players
        // 100 = Staff
        // 142 = ClubItems
        // Consumables are different

        public ClubItemRequest()
        {
            _listType = 1;
        }

        public async Task<ClubItemResponse> PerformRequestAsync()
        {
            var uriString = Resources.FutHome + Resources.MyClub + $"&type={_listType}";
            uriString += "&_=" + DateTime.Now.ToUnixTime();
            AddCommonHeaders();

            var clubItemResponseMessage = await HttpClient
                    .GetAsync(uriString)
                    .ConfigureAwait(false);

            return await DeserializeAsync<ClubItemResponse>(clubItemResponseMessage).ConfigureAwait(false);
        }
    }
}
