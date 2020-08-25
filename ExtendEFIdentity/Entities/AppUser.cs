using Microsoft.AspNetCore.Identity;
namespace ExtendEFIdentity.Entities
{
    public class AppUser : IdentityUser
    {
        public string FullName { get; set; }
    }

}