using System.ComponentModel.DataAnnotations;
namespace IdentityNetCore.Models
{
    public class SigninViewModel
    {
        [Required(ErrorMessage = "Username is reguired")]
        [DataType(DataType.EmailAddress)]
        public string Username { get; set; }
        
        [Required(ErrorMessage = "Passowrd must be provided")]
        [DataType(DataType.Password)]
        public string Password { get; set; }
        public bool RememberMe { get; set; }
    }
}