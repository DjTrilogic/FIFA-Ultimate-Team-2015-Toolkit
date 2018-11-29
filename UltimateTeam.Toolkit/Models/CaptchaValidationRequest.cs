using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace UltimateTeam.Toolkit.Models
{
    public class CaptchaValidationRequest
    {
        [JsonProperty("funCaptchaToken")]
        public string FunCaptchaToken { get; set; }
    }
}