using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using AESEncryption.Models;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AESEncryption.Controllers
{
    public class HomeController : Controller
    {
        private const string salt = "d5fg4df5sg4ds5fg45sdfg4";
        private const int SizeOfBuffer = 1024 * 8;
        public ActionResult Index()
        {
            return View();
        }

        public void EncryptFile(string inputPath, string outputPath, string password)
        {
            var input = new FileStream(inputPath, FileMode.Open,FileAccess.Read);
            var output = new FileStream(outputPath, FileMode.OpenOrCreate, FileAccess.Write);

            var algorithm = new AesManaged { KeySize = 256, BlockSize = 128 };
            var key = new Rfc2898DeriveBytes(password, Encoding.ASCII.GetBytes(salt));

            algorithm.Key = key.GetBytes(algorithm.KeySize / 8);
            algorithm.IV = key.GetBytes(algorithm.BlockSize / 8);

            using (var encryptedStream = new CryptoStream(output, algorithm.CreateEncryptor(), CryptoStreamMode.Write))
            {
                CopyStream(input, encryptedStream);
            }
        }

        public void DecryptFile(string inputPath, string outputPath, string password)
        {
            var input = new FileStream(inputPath, FileMode.Open, FileAccess.Read);
            var output = new FileStream(outputPath, FileMode.OpenOrCreate, FileAccess.Write);

            var algorithm = new AesManaged { KeySize = 256, BlockSize = 128 };
            var key = new Rfc2898DeriveBytes(password, Encoding.ASCII.GetBytes(salt));

            algorithm.Key = key.GetBytes(algorithm.KeySize / 8);
            algorithm.IV = key.GetBytes(algorithm.BlockSize / 8);

            using (var decryptededStream = new CryptoStream(output, algorithm.CreateDecryptor(), CryptoStreamMode.Write))
            {
                CopyStream(input, decryptededStream);
            }
        }

        private static void CopyStream(Stream input, Stream output)
        {
            using (output)
            using (input)
            {
                byte[] buffer = new byte[SizeOfBuffer];
                int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    output.Write(buffer, 0, read);
                }
            }
        }
    }
}