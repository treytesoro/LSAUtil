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
            using (LSAtool lt = new LSAtool("IDONTEXIST"))
            {

                // Setting the secret
                // Console.WriteLine("Setting secret");
                //if (!lt.SetSecret("test")) {
                //    Console.WriteLine("Error setting secret");
                //}

                // Getting the secret
                Console.WriteLine("Getting secret");
                try
                {
                    String secret = lt.GetSecret();
                    Console.WriteLine(secret);
                }
                catch (Exception)
                {
                    Console.WriteLine("Could not get the requested secret.");
                }

                Console.WriteLine("Press any key to delete secret and exit");
                Console.Read();

                if (!lt.DeleteSecret())
                {
                    Console.WriteLine("Error deleting secret");
                }

            }
        }
    }
}
