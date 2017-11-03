using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UltimateTeam.Toolkit.Exceptions
{
    public class WrongCredentialsException : FutException
    {
        public WrongCredentialsException(string message) : base(message)
        {
        }
    }
}
