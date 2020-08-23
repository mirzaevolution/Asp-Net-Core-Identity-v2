using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace BasicCustomIdentity.Models
{
    public class LoginViewModel
    {
        [Display(Name = "User Name"), Required]
        public string UserName { get; set; }
        [Display(Name = "Password"), Required, DataType(DataType.Password)]
        public string Password { get; set; }
    }
}
