using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace BasicCustomIdentity.Models
{
    public class RegisterUserViewModel
    {
        [Display(Name = "Full Name"), Required]
        public string FullName { get; set; }
        [Display(Name = "User Name"), Required]
        public string UserName { get; set; }
        [Display(Name = "Password"),Required,DataType(DataType.Password)]
        public string Password { get; set; }
        [Display(Name = "Confirm Password"), Required, 
            DataType(DataType.Password), Compare(nameof(Password))]
        public string ConfirmPassword { get; set; }
    }
}
