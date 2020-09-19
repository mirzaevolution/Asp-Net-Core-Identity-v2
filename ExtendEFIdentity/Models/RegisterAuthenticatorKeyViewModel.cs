using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ExtendEFIdentity.Models
{
    public class RegisterAuthenticatorKeyViewModel
    {
        public string AuthenticatorKey { get; set; }
        public string Token { get; set; }

        public bool AlreadyActivated { get; set; }
    }
}
