namespace DualAuthCoreExample.Models
{
    using System.ComponentModel.DataAnnotations;

    public class CredentialsViewModel
    {
        [Required]
        public string UserName { get; set; }

        [Required]
        [MinLength(10)]
        public string Password { get; set; }
    }
}