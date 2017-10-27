namespace DualAuthCoreExample.Options
{
    public class AuthOptions
    {
        public int ExpirationMinutes { get; set; }

        public int LockoutFor { get; set; }

        public int MaxFailedLoginAttempts { get; set; }

        public string PwnedPasswordApi { get; set; }

        public int RequiredPasswordLength { get; set; }
    }
}
