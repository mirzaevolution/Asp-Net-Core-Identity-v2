using System.ComponentModel.DataAnnotations;

namespace ExtendEFIdentity.Models
{
    public class TwoFactorTokenViewModel
    {
        [Required]
        public string UserId { get; set; }
        [Required]
        public string Token { get; set; }
        [Required]
        public string Provider { get; set; }
    }
}
