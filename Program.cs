using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BouncyCastleAESAlgorithmCBCMode
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var cryptographicService = new CryptographicService();
            
            var medicalHistory = "Hypertension diagnosed in 2018, managed with medication (Lisinopril). " +
                "No known allergies. Routine check-ups every year.";
            var encryptionKey = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

            var encryptedMedicalHistory = cryptographicService.CheckEncryption(medicalHistory, encryptionKey);
            var decryptedMedicalHistory = cryptographicService.CheckDecryption(encryptedMedicalHistory, encryptionKey);

        }
    }
}
