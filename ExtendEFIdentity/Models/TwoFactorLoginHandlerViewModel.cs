using System.Collections.Generic;

namespace ExtendEFIdentity.Models
{
    public class TwoFactorLoginHandlerViewModel
    {
        public string Email { get; set; }
        public string Provider { get; set; }
        public IList<string> Providers { get; set; } = new List<string>();
    }
}