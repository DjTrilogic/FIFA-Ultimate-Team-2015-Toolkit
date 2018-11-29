using System;

namespace UltimateTeam.Toolkit.Exceptions
{
    public class UnhandledCaptchaException : FutException
    {
        public UnhandledCaptchaException(string message) : base(message)
        {
        }

        public UnhandledCaptchaException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}