using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Serilog;
using UltimateTeam.Toolkit.Constants;
using UltimateTeam.Toolkit.Exceptions;
using UltimateTeam.Toolkit.Extensions;
using UltimateTeam.Toolkit.Models;
using UltimateTeam.Toolkit.Services;

namespace UltimateTeam.Toolkit.Requests
{
    public class LoginRequest : FutRequestBase, IFutRequest<LoginResponse>
    {
        private IHasher _hasher;

        public IHasher Hasher
        {
            get => _hasher ?? (_hasher = new Hasher());
            set => _hasher = value;
        }

        public AuthenticationType AuthType { get; set; }

        public ITwoFactorCodeProvider TwoFactorCodeProvider { get; set; }

        public ICaptchaSolver CaptchaSolver { get; set; }

        public LoginPriority LoginPriority { get; set; }

        public LoginRequest(LoginDetails loginDetails, ITwoFactorCodeProvider twoFactorCodeProvider, LoginPriority loginPriority)
        {
            if (loginDetails.Username == null || loginDetails.Password == null)
            {
                throw new FutException($"No Username or Password provided for {LoginDetails?.AppVersion}.");
            }
            LoginDetails = loginDetails;
            LoginPriority = loginPriority;
            TwoFactorCodeProvider = twoFactorCodeProvider;
        }

        public async Task<LoginResponse> PerformRequestAsync()
        {
            try
            {
                var mainPageResponseMessage = await GetMainPageAsync().ConfigureAwait(false);
                var _ = await LoginAsync(mainPageResponseMessage).ConfigureAwait(false);
                var accessToken = LoginResponse.AuthCode.Code;
                var pidData = await GetPidDataAsync(accessToken).ConfigureAwait(false);

                LoginResponse.Persona.NucUserId = pidData.Pid.ExternalRefValue;
                LoginResponse.Persona.Dob = pidData.Pid.Dob;


                LoginResponse.Shards = await GetShardsAsync().ConfigureAwait(false);
                LoginResponse.UserAccounts = await GetUserAccountsAsync(LoginDetails).ConfigureAwait(false);

                var matchingPersona = MatchPersona(LoginResponse.UserAccounts);
                ValidatePersona(matchingPersona);


                LoginResponse.Persona.NucPersId = matchingPersona.PersonaId;
                LoginResponse.Persona.DisplayName = matchingPersona.PersonaName;

                LoginResponse.AuthCode = await GetAuthCodeAsync(accessToken).ConfigureAwait(false);

                LoginResponse.AuthData = await AuthAsync().ConfigureAwait(false);
                LoginResponse.PhishingToken = await ValidateAsync(LoginDetails).ConfigureAwait(false);

                return LoginResponse;
            }
            catch (Exception e)
            {
                throw new LoginFailedException($"Unable to login to {LoginDetails.AppVersion}", e);
            }
        }

        private static void ValidatePersona(Persona matchingPersona)
        {
            if (matchingPersona.UserState == "RETURNING_USER_EXPIRED")
            {
                //throw new LoginFailedException("Appears your Early Access has expired.");
            }
        }

        private async Task<PidData> GetPidDataAsync(string authCode)
        {
            AddLoginHeaders();
            AddAuthorizationHeader(authCode);
            var pidDataResponseMessage = await HttpClient.GetAsync(string.Format(Resources.Pid)).ConfigureAwait(false);
            var pidData = await DeserializeAsync<PidData>(pidDataResponseMessage).ConfigureAwait(false);

            if (pidData?.Pid == null)
                throw new Exception($"Got no PID Data during the Login process to to {LoginDetails?.AppVersion}.");
            return pidData;
        }

        private async Task<AuthCode> GetAuthCodeAsync(string accessToken)
        {
            AddLoginHeaders(true);
            var authCodeResponseMessage = await HttpClient.GetAsync(string.Format(Resources.AuthCode, accessToken)).ConfigureAwait(false);
            var authCode = await DeserializeAsync<AuthCode>(authCodeResponseMessage).ConfigureAwait(false);

            if (authCode?.Code == null)
                throw new Exception($"Got no AuthCode during the Login process to {LoginDetails?.AppVersion}.");

            return authCode;
        }

        protected async Task<HttpResponseMessage> SetTwoFactorTypeAsync(HttpResponseMessage mainPageResponseMessage)
        {
            HttpResponseMessage loginResponseMessage;

            if (AuthType == AuthenticationType.Email)
            {
                loginResponseMessage = await HttpClient.PostAsync(mainPageResponseMessage.RequestMessage.RequestUri, new FormUrlEncodedContent(
                                                                                                                            new[]
                                                                                                                            {
                                                                                                                            new KeyValuePair<string, string>("_eventId", "submit"),
                                                                                                                                new KeyValuePair<string, string>("codeType", "EMAIL"),
                                                                                                                            }))
                    .ConfigureAwait(false);
            }
            else
            {
                loginResponseMessage = await HttpClient.PostAsync(mainPageResponseMessage.RequestMessage.RequestUri, new FormUrlEncodedContent(
                                                                                                                            new[]
                                                                                                                            {
                                                                                                                            new KeyValuePair<string, string>("_eventId", "submit"),
                                                                                                                            new KeyValuePair<string, string>("codeType", "APP"),
                                                                                                                            }))
                    .ConfigureAwait(false);
            }

            return loginResponseMessage;
        }

        protected async Task<HttpResponseMessage> SetTwoFactorCodeAsync(HttpResponseMessage loginResponse)
        {
            loginResponse = await LoginForwarder(loginResponse).ConfigureAwait(false);
            var contentData = await loginResponse.Content.ReadAsStringAsync().ConfigureAwait(false);

            AuthType = AuthenticationType.Unknown;
            if (TwoFactorCodeProvider.HandledAuthType == AuthenticationType.Email &&(contentData.Contains("send you a code to:") || contentData.Contains("Send to my Primary Email") || contentData.Contains("In order to verify your identity")) )
            {
                AuthType = AuthenticationType.Email;
            }
            else if (TwoFactorCodeProvider.HandledAuthType == AuthenticationType.App && contentData.Contains("App Authenticator"))
            {
                AuthType = AuthenticationType.App;
            }

            var sent = await SetTwoFactorTypeAsync(loginResponse).ConfigureAwait(false);
            loginResponse = await LoginForwarder(sent).ConfigureAwait(false);


            var twoFactorCode = await TwoFactorCodeProvider.GetTwoFactorCodeAsync(AuthType).ConfigureAwait(false);

            if (twoFactorCode.Length < 6 || twoFactorCode.Length > 8)
            {
                throw new Exception($"Two Factor Code MUST be 6 to 8 digits long {LoginDetails?.AppVersion}.");
            }

            if (AuthType == AuthenticationType.Unknown)
            {
                throw new Exception($"Unable to determine AuthType (i.e. App Authenticator or E-Mail) for {LoginDetails?.AppVersion}.");
            }

            AddRefererHeader(loginResponse.RequestMessage.RequestUri.ToString());

            var codeResponseMessage = await HttpClient.PostAsync(loginResponse.RequestMessage.RequestUri,
                new FormUrlEncodedContent(
                    new[]
                    {
                        new KeyValuePair<string, string>("oneTimeCode", twoFactorCode),
                        new KeyValuePair<string, string>("_eventId", "submit"),
                        new KeyValuePair<string, string>("trustThisDevice", "on"),
                        new KeyValuePair<string, string>("_trustThisDevice", "on"),
                    }))
                .ConfigureAwait(false);

            var codeResponseMessageContent = await codeResponseMessage.Content.ReadAsStringAsync().ConfigureAwait(false);

            if (codeResponseMessageContent.Contains("Incorrect code entered"))
            {
                throw new Exception($"Incorrect Two Factor Code entered ({twoFactorCode}) for {LoginDetails?.AppVersion}.");
            }

            return codeResponseMessage;
        }

        protected async Task<HttpResponseMessage> LoginForwarder(HttpResponseMessage responseMessage)
        {
            var contentData = await responseMessage.Content.ReadAsStringAsync().ConfigureAwait(false);
            if (contentData.Contains("https://signin.ea.com:443/p/web2/login?execution="))
            {
                Match executionIdMatch = Regex.Match(contentData, @"'https:\/\/signin\.ea\.com:443\/p\/web2\/login\?execution=([A-Za-z0-9\-]+)&initref=(.*)';");

                string executionId = executionIdMatch.Groups[1].Value;
                string initRef = executionIdMatch.Groups[2].Value;
                var forwardResponseMessage = await HttpClient.GetAsync($"https://signin.ea.com:443/p/web2/login?execution={executionId}&initref={initRef}&_eventId=end")
                    .ConfigureAwait(false);

                return forwardResponseMessage;
            }
            return responseMessage;
        }

        protected async Task<Shards> GetShardsAsync()
        {
            AddLoginHeaders();
            HttpClient.AddRequestHeader(NonStandardHttpHeaders.NucleusId, LoginResponse.Persona.NucUserId);
            //HttpClient.AddRequestHeader(NonStandardHttpHeaders.PowSessionId, LoginResponse.POWSessionId);

            var shardsResponseMessage = await HttpClient.GetAsync(string.Format(Resources.Shards, DateTime.Now.ToUnixTime())).ConfigureAwait(false);
            var _ = await shardsResponseMessage.Content.ReadAsStringAsync().ConfigureAwait(false);
            var shards = await DeserializeAsync<Shards>(shardsResponseMessage).ConfigureAwait(false);

            if (shards?.ShardInfo == null || shards.ShardInfo.Count <= 0)
            {
                throw new Exception($"Unable to get Shards {LoginDetails?.AppVersion}.");
            }
            return shards;
        }

        protected async Task<UserAccounts> GetUserAccountsAsync(LoginDetails loginDetails)
        {
            AddLoginHeaders();
            HttpClient.AddRequestHeader(NonStandardHttpHeaders.NucleusId, LoginResponse.Persona.NucUserId);
            HttpClient.AddRequestHeader(NonStandardHttpHeaders.SessionId, string.Empty);

            var accountInfoResponseMessage = await HttpClient.GetAsync(string.Format(Resources.AccountInfo, DateTime.Now.ToUnixTime())).ConfigureAwait(false);
            var _ = await accountInfoResponseMessage.Content.ReadAsStringAsync().ConfigureAwait(false);
            var userAccounts = await DeserializeAsync<UserAccounts>(accountInfoResponseMessage).ConfigureAwait(false);

            if (userAccounts?.UserAccountInfo?.Personas == null || !userAccounts.UserAccountInfo.Personas.Any())
            {
                throw new Exception($"Unable to get Personas {loginDetails?.AppVersion}.");
            }
            return userAccounts;
        }

        private Persona MatchPersona(UserAccounts userAccounts)
        {
            Persona matchingPersona;
            try
            {
                matchingPersona = userAccounts.UserAccountInfo.Personas.First(n => n.UserClubList.First().Platform == GetPlatform(LoginDetails.Platform));
            }
            catch (Exception e)
            {
                throw new Exception($"Unable to match a valid Persona for {LoginDetails?.AppVersion}.", e);
            }
            return matchingPersona;
        }

        protected async Task<PhishingToken> ValidateAsync(LoginDetails loginDetails)
        {
            AddLoginHeaders();
            HttpClient.AddRequestHeader(NonStandardHttpHeaders.NucleusId, LoginResponse.Persona.NucUserId);

            HttpClient.AddRequestHeader(NonStandardHttpHeaders.SessionId, LoginResponse.AuthData.Sid);
            var validateResponseMessage = await HttpClient.GetAsync(String.Format(Resources.ValidateQuestion, DateTime.Now.ToUnixTime())).ConfigureAwait(false);

            var validateResponseMessageContent = await validateResponseMessage.Content.ReadAsStringAsync().ConfigureAwait(false);
            if (validateResponseMessageContent.Contains("Fun Captcha Triggered"))
            {
                await SolveCaptcha();
                validateResponseMessage = await HttpClient.GetAsync(String.Format(Resources.ValidateQuestion, DateTime.Now.ToUnixTime())).ConfigureAwait(false);
                validateResponseMessageContent = await validateResponseMessage.Content.ReadAsStringAsync().ConfigureAwait(false);
            }
            if (validateResponseMessageContent.Contains("Already answered question") ||
                validateResponseMessageContent.Contains("Feature Disabled"))
            {
                return null;
            }

            validateResponseMessage = await HttpClient.PostAsync(String.Format(Resources.ValidateAnswer, Hasher.Hash(loginDetails.SecretAnswer)), new FormUrlEncodedContent(
                  new[]
                  {
                    new KeyValuePair<string, string>("answer", Hasher.Hash(loginDetails.SecretAnswer))
                  }))
                .ConfigureAwait(false);
            var phishingToken = await DeserializeAsync<PhishingToken>(validateResponseMessage).ConfigureAwait(false);
            var _ = await validateResponseMessage.Content.ReadAsStringAsync().ConfigureAwait(false);

            if (phishingToken.Code != "200" || phishingToken.Token == null)
            {
                throw new Exception($"Unable to get Phishing Token {LoginDetails?.AppVersion}.");
            }

            return phishingToken;

        }

        protected async Task SolveCaptcha()
        {
            if (CaptchaSolver == null)
            {
                throw new UnhandledCaptchaException($"Captcha triggered but captcha solver was disabled/undefined");
            }

            if (!CaptchaSolver.IsEnabled)
            {
                throw new UnhandledCaptchaException($"Captcha triggered but the captcha solver is disabled");
            }

            var token = await CaptchaSolver.Solve(this).ConfigureAwait(false);
            var requestBody = JsonConvert.SerializeObject(token);
            var validationUri = Resources.FutHome + Resources.FunCaptchaValidate;
            var _ = await HttpClient.PostAsync(validationUri, new StringContent(requestBody)).ConfigureAwait(false);
        }

        protected async Task<Auth> AuthAsync()
        {
            var loginPriority = LoginPriority == LoginPriority.Low ? "4" : "5";
            AddLoginHeaders(true);
            //HttpClient.AddRequestHeader(NonStandardHttpHeaders.SessionId, string.Empty);
            //HttpClient.AddRequestHeader(NonStandardHttpHeaders.PowSessionId, string.Empty);
            //HttpClient.AddRequestHeader(NonStandardHttpHeaders.Origin, @"https://www.easports.com");
            var httpContent = $@"{{""isReadOnly"":false,""sku"":""{Resources.Sku}"",""clientVersion"":{Resources.ClientVersion},""locale"":""en-US"",""method"":""authcode"",""priorityLevel"":{loginPriority},""identification"":{{""authCode"":""{LoginResponse.AuthCode.Code}"",""redirectUrl"":""nucleus:rest""}},""nucleusPersonaId"":""{LoginResponse.Persona.NucPersId}"",""gameSku"":""{GetGameSku(LoginDetails.Platform)}""}}";
            var authResponseMessage = await HttpClient.PostAsync(Resources.Auth, new StringContent(httpContent)).ConfigureAwait(false);

            var authResponse = await DeserializeAsync<Auth>(authResponseMessage).ConfigureAwait(false);
            var _ = await authResponseMessage.Content.ReadAsStringAsync().ConfigureAwait(false);

            if (authResponse.Sid == null)
            {
                throw new Exception($"Unable to get Session Id {LoginDetails?.AppVersion}.");
            }

            return authResponse;
        }

        protected async Task<HttpResponseMessage> LoginAsync(HttpResponseMessage mainPageResponseMessage)
        {
            var loginResponseMessage = await HttpClient.PostAsync(mainPageResponseMessage.RequestMessage.RequestUri, new FormUrlEncodedContent(
                    new[]
                    {
                        new KeyValuePair<string, string>("email", LoginDetails.Username),
                        new KeyValuePair<string, string>("password", LoginDetails.Password),
                        new KeyValuePair<string, string>("_eventId", "submit"),
                        new KeyValuePair<string, string>("country", "UK"),
                        new KeyValuePair<string, string>("phoneNumber", ""),
                        new KeyValuePair<string, string>("passwordForPhone", ""),
                        new KeyValuePair<string, string>("_rememberMe", "on"),
                        new KeyValuePair<string, string>("rememberMe", "on"),
                        new KeyValuePair<string, string>("gCaptchaResponse", ""),
                        new KeyValuePair<string, string>("isPhoneNumberLogin", "false"),
                        new KeyValuePair<string, string>("isIncompletePhone", "")
                    }))
                .ConfigureAwait(false);
            var contentData = await loginResponseMessage.Content.ReadAsStringAsync().ConfigureAwait(false);

            if (contentData.Contains("Your credentials are incorrect or have expired") || contentData.Contains("Email address is invalid"))
            {
                throw new WrongCredentialsException($"Wrong credentials for {LoginDetails?.AppVersion}.");
            }

            var forwardedResponse = await LoginForwarder(loginResponseMessage).ConfigureAwait(false);
            contentData = await forwardedResponse.Content.ReadAsStringAsync().ConfigureAwait(false);
            loginResponseMessage = forwardedResponse;


            if (contentData.Contains("Login Verification"))
            {
                loginResponseMessage = await SetTwoFactorCodeAsync(loginResponseMessage).ConfigureAwait(false);
                var _ = await loginResponseMessage.Content.ReadAsStringAsync().ConfigureAwait(false);
            }

            if (loginResponseMessage.RequestMessage.RequestUri.AbsoluteUri.Contains("access_token="))
            {
                var _ = await loginResponseMessage.Content.ReadAsStringAsync().ConfigureAwait(false);
                LoginResponse.AuthCode.Code = loginResponseMessage.RequestMessage.RequestUri.AbsoluteUri.Substring(loginResponseMessage.RequestMessage.RequestUri.AbsoluteUri.IndexOf("=", StringComparison.Ordinal) + 1);
                LoginResponse.AuthCode.Code = LoginResponse.AuthCode.Code.Substring(0, LoginResponse.AuthCode.Code.IndexOf('&'));
            }

            return loginResponseMessage;
        }

        protected async Task<HttpResponseMessage> GetMainPageAsync()
        {

            HttpClient.ClearRequestHeaders();

            Log.Verbose("Getting MainPage...");
            var mainPageResponseMessage = await HttpClient.GetAsync(Resources.Home).ConfigureAwait(false);
            Log.Verbose("Main page response received {mainPageResponseMessage}", mainPageResponseMessage);
            return mainPageResponseMessage;
        }

        protected string GetGameSku(Platform platform)
        {
            switch (platform)
            {
                case Platform.Ps3:
                    return $"{Resources.GameSku}PS3";
                case Platform.Ps4:
                    return $"{Resources.GameSku}PS4";
                case Platform.Xbox360:
                    return $"{Resources.GameSku}XBX";
                case Platform.XboxOne:
                    return $"{Resources.GameSku}XBO";
                case Platform.Pc:
                    return $"{Resources.GameSku}PCC";
                case Platform.Switch:
                    return $"{Resources.GameSku}SWI";
                default:
                    throw new ArgumentOutOfRangeException(nameof(platform));
            }
        }

        protected static string GetPlatform(Platform platform)
        {
            switch (platform)
            {
                case Platform.Ps3:
                case Platform.Ps4:
                    return "ps3";
                case Platform.Xbox360:
                case Platform.XboxOne:
                    return "360";
                case Platform.Pc:
                    return "pc";
                case Platform.Switch:
                    return "swi";
                default:
                    throw new ArgumentOutOfRangeException(nameof(platform));
            }
        }
    }
}