using System;

namespace UltimateTeam.Toolkit.Exceptions
{
    public class LoginFailedException : FutException
    {
        public LoginFailedException(string message) : base(message)
        {
        }

        public LoginFailedException(string message, Exception e) : base(message, e)
        {
        }
    }
}
