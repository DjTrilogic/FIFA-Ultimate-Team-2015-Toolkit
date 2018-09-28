using System.Text.RegularExpressions;
using System.Threading.Tasks;
using UltimateTeam.Toolkit.Models;
using UltimateTeam.Toolkit.Requests;

namespace UltimateTeam.Toolkit.Services
{
    public class PinEventsHandler
    {
        private readonly LoginResponse _response;
        private readonly IHttpClient _httpClient;
        private string plat;
        private string taxv;
        private string tidt;
        private string sku;
        private string rel;
        private string gid;
        private string et;
        private string pidt;
        private string v;

        public PinEventsHandler(LoginResponse response, IHttpClient httpClient)
        {
            _response = response;
            _httpClient = httpClient;
        }

        public async Task Initialize()
        {
            var response = await _httpClient.GetAsync("https://www.easports.com/fifa/ultimate-team/web-app/js/compiled_1.js");
            var content = await response.Content.ReadAsStringAsync();
            var match = Regex.Match(content, "plat:\"(.+?)\"");
            plat = match.Success ? match.Groups[1].Value : "web";
            match = Regex.Match(content, "taxv:\"(.+?)\"");
            taxv = match.Success ? match.Groups[1].Value : null;
            match = Regex.Match(content, "tidt:\"(.+?)\"");
            tidt = match.Success ? match.Groups[1].Value : null;
            sku = _response.Persona.Sku ?? Regex.Match(content, "enums.SKU.FUT=\"(.+?)\"").Groups[1].Value;
            rel = Regex.Match(content, "rel:\"(.+?)\"").Groups[1].Value;
            gid = Regex.Match(content, "gid:\"([0-9]+?)\"").Groups[1].Value;
            et = Regex.Match(content, "et:\"(.+?)\"").Groups[1].Value;
            pidt = Regex.Match(content, "pidt:\"(.+?)\"").Groups[1].Value;
            v = Regex.Match(content, "APP_VERSION=\"([0-9\\.]+?)\"").Groups[1].Value;

            response = await _httpClient.GetAsync("https://www.easports.com/fifa/ultimate-team/web-app/js/compiled_2.js");
            content = await response.Content.ReadAsStringAsync();
            if (taxv == null)
            {
                match = Regex.Match(content, "PinManager.TAXONOMY_VERSION=([0-9\\.]+)");
                taxv = match.Success ? match.Groups[1].Value : "1.1";
            }
            tidt = tidt ?? "easku";

        }
    }
}
