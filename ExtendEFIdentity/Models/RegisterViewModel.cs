using System.ComponentModel.DataAnnotations;

namespace ExtendEFIdentity.Models
{
    public class RegisterViewModel
    {
        [Display(Name = "Full Name"), Required]
        public string FullName { get; set; }
        [Display(Name = "Email"), DataType(DataType.EmailAddress), Required]
        public string Email { get; set; }
        [Display(Name = "Password"), Required, DataType(DataType.Password)]
        public string Password { get; set; }
        [Display(Name = "Confirm Password"), Required,
            DataType(DataType.Password), Compare(nameof(Password))]
        public string ConfirmPassword { get; set; }
    }
}
