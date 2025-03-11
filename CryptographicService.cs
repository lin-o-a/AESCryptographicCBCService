using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Text;

namespace BouncyCastleAESAlgorithmCBCMode
{
    public class CryptographicService
    {
        public CryptographicService() { }
        
        #region private functions
        private byte[] normalizeDataForEncryption(string dataToEncrypt) {
            var convertedData = convertToBytes(dataToEncrypt);
            var paddedData = padData(convertedData);

            return paddedData;
        }
        private byte[] convertToBytes(string data)
        {
            byte[] convertedData = Encoding.UTF8.GetBytes(data);
            return convertedData;
        }

        private byte[] padData(byte[] data) {
            int bytesInData = data.Length;
            int blockSizeInAES = 16;
            int bytesInLastDataBlock = bytesInData % blockSizeInAES;

            int paddedBytesToAdd = (bytesInLastDataBlock == 0) ? blockSizeInAES : blockSizeInAES - bytesInLastDataBlock;

            byte[] paddedData = new byte[bytesInData + paddedBytesToAdd];
            Array.Copy(data, 0, paddedData, 0, bytesInData);

            //This is PKCS#7 padding value
            byte paddingValue = (byte)paddedBytesToAdd;
            
            for (int i = bytesInData; i < paddedData.Length; i++) {
                paddedData[i] = paddingValue;
            }

            return paddedData;
        }

        private CbcBlockCipher setUpEncryptionService(byte[] encryptionKey, bool isEncryption) {
            AesEngine aesEngine = new AesEngine();
            CbcBlockCipher cbcBlockCipher = new CbcBlockCipher(aesEngine);

            KeyParameter keyParam = new KeyParameter(encryptionKey);
            
            byte[] initializationVector = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
            ParametersWithIV parametersWithIV = new ParametersWithIV(keyParam, initializationVector);

            cbcBlockCipher.Init(isEncryption, parametersWithIV);

            return cbcBlockCipher;
        }

        private byte[] CreateEncryptionHolder(byte[] normalizedData, int AESBlockSize) {
            int outputSize = (int)Math.Ceiling((double)normalizedData.Length / AESBlockSize) * AESBlockSize;
            return new byte[outputSize];
        }
        #endregion

        #region public functions
        public byte[] CheckEncryption(string dataToEncrypt, byte[] encryptionKey)
        {
            var normalizedData = normalizeDataForEncryption(dataToEncrypt);
            var encryptionService = setUpEncryptionService(encryptionKey, true);

            int encryptionBlockSize = encryptionService.GetBlockSize();
            var cipherHolder = CreateEncryptionHolder(normalizedData, encryptionBlockSize);

            for (int dataCursor = 0; dataCursor < normalizedData.Length; dataCursor += encryptionBlockSize)
            {
                encryptionService.ProcessBlock(normalizedData, dataCursor, cipherHolder, dataCursor);
            }

            return cipherHolder;
        }

        public string CheckDecryption(byte[] cipherToDecrypt, byte[] encryptionKey)
        {
            var encryptionService = setUpEncryptionService(encryptionKey, false);

            int blockSize = encryptionService.GetBlockSize();
            byte[] plainText = new byte[cipherToDecrypt.Length];

            for (int offset = 0; offset < cipherToDecrypt.Length; offset += blockSize)
            {
                encryptionService.ProcessBlock(cipherToDecrypt, offset, plainText, offset);
            }

            return Encoding.UTF8.GetString(plainText);
        }
        #endregion
    }
}
