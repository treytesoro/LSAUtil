using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using LSAutil;

namespace lsatest
{
    internal class Program
    {
        static void Main(string[] args)
        {
            // Create an LSAtool object targeting DefaultPassword
            LSAtool lt = new LSAtool("DefaultPassword");

            // Setting the secret
            lt.SetSecret("Some_secret_password");

            // Getting the secret
            String secret = lt.GetSecret();
        }
    }
}
