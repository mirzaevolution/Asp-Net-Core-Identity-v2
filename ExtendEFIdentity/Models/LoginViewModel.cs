using System.ComponentModel.DataAnnotations;

namespace ExtendEFIdentity.Models
{
    public class LoginViewModel
    {
        [Display(Name = "Email"), DataType(DataType.EmailAddress), Required]
        public string Email { get; set; }
        [Display(Name = "Password"), Required, DataType(DataType.Password)]
        public string Password { get; set; }
    }
}
