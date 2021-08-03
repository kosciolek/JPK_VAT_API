using System;
using System.IO;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using RestSharp;

namespace jpk
{
    class Program
    {
        static void Prepare()
        {
            string filename = "jpk.xml";
            string compressedEncryptedFilename = $"{filename}.zip.aes";


            byte[] sha256hash; //asd
            using (SHA256 sha = SHA256.Create())
                sha256hash = sha.ComputeHash(File.ReadAllBytes(filename));
            string sha256hashAsBase64 = Convert.ToBase64String(sha256hash);

            Directory.CreateDirectory("tempDir");
            File.Copy(filename, "./tempDir/" + filename, true);
            if (File.Exists("tempDir.zip"))
            {
                File.Delete("tempDir.zip");
            }

            System.IO.Compression.ZipFile.CreateFromDirectory("tempDir", "tempDir.zip");
            //TODO Delete the temp dir.
            //File.Delete("tempDir");


            byte[] aesKey;
            byte[] aesIV;
            using (RijndaelManaged aes = new RijndaelManaged()
                {BlockSize = 256, Padding = PaddingMode.PKCS7, Mode = CipherMode.CBC, KeySize = 256})
            {
                aes.GenerateIV();
                aes.GenerateKey();
                aesKey = aes.Key;
                aesIV = aes.IV;

                using (FileStream inputFs = new FileStream("tempDir.zip", FileMode.Open))
                using (FileStream outputFs = new FileStream(compressedEncryptedFilename, FileMode.Create))
                using (CryptoStream cryptostream =
                    new CryptoStream(outputFs, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] buffer = new byte[1048576];
                    int read;
                    while ((read = inputFs.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        cryptostream.Write(buffer, 0, read);
                    }
                }
            }

            File.Delete($"tempDir.zip");

            string aesKeyAsBase64 = Convert.ToBase64String(aesKey);
            string aesIVAsBase64 = Convert.ToBase64String(aesIV);

            byte[] md5hash;
            string md5hashAsBase64;
            using (MD5 md5 = MD5.Create())
                md5hash = md5.ComputeHash(File.ReadAllBytes(compressedEncryptedFilename));

            md5hashAsBase64 = Convert.ToBase64String(md5hash);

            byte[] encryptedAesKey;
            string encryptedAesKeyAsBase64;
            using (RSACryptoServiceProvider rsa = PemKeyUtils.GetRSAProviderFromPemFile(@"pubkey.pem"))
            {
                encryptedAesKey = rsa.Encrypt(aesKey, false);
            }

            encryptedAesKeyAsBase64 = Convert.ToBase64String(encryptedAesKey);

            string jpkXml = File.ReadAllText(filename);
            string wersjaSchemy = Regex.Match(jpkXml, "wersjaSchemy=\"(.*?)\"").Groups[1].ToString();
            string kodSystemowy = Regex.Match(jpkXml, "kodSystemowy=\"(.*?)\"").Groups[1].ToString();
            string kodFormularza = Regex.Match(jpkXml, "<(.*?:)?KodFormularza.*?>(.*?)</\\1?KodFormularza>").Groups[2]
                .ToString();
            string originalLength = new FileInfo(filename).Length.ToString();
            string compressedEncryptedLength = new FileInfo(compressedEncryptedFilename).Length.ToString();

            string initUploadXml =
                $"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><InitUpload xmlns=\"http://e-dokumenty.mf.gov.pl\"><DocumentType>JPK</DocumentType><Version>01.02.01.20160617</Version><EncryptionKey algorithm=\"RSA\" mode=\"ECB\" padding=\"PKCS#1\" encoding=\"Base64\">{aesKeyAsBase64}</EncryptionKey><DocumentList><Document><FormCode systemCode=\"{kodSystemowy}\" schemaVersion=\"{wersjaSchemy}\">{kodFormularza}</FormCode><FileName>{filename}</FileName><ContentLength>{originalLength}</ContentLength><HashValue algorithm=\"SHA-256\" encoding=\"Base64\">{sha256hashAsBase64}=</HashValue><FileSignatureList filesNumber=\"1\"><Packaging><SplitZip type=\"split\" mode=\"zip\"/></Packaging><Encryption><AES size=\"256\" block=\"16\" mode=\"CBC\" padding=\"PKCS#7\"><IV bytes=\"16\" encoding=\"Base64\">{aesIVAsBase64}</IV></AES></Encryption><FileSignature><OrdinalNumber>1</OrdinalNumber><FileName>{compressedEncryptedFilename}</FileName><ContentLength>{compressedEncryptedLength}</ContentLength><HashValue algorithm=\"MD5\" encoding=\"Base64\">{md5hashAsBase64}</HashValue></FileSignature></FileSignatureList></Document></DocumentList></InitUpload>";

            File.WriteAllText("asd.txt", initUploadXml);
        }


        private static void TestMethod()
        {
            const bool validateSignature = true;
            const string baseUrl = @"https://test-e-dokumenty.mf.gov.pl/api/Storage";
            const string xmlFileName = @"enveloping.xades";

            RestClient client = new RestClient(baseUrl);
            RestRequest request = new RestRequest("InitUploadSigned", Method.POST);
            request.AddParameter("enableValidateQualifiedSignature", validateSignature.ToString());

            using (FileStream fileStream = new FileStream(xmlFileName, FileMode.Open))
            using (StreamReader streamReader = new StreamReader(fileStream))
            {
                request.AddXmlBody(streamReader.ReadToEnd());
            }

            IRestResponse response = client.Execute(request);
            string content = response.Content;
            Console.Write(content);
            Console.ReadKey();
        }

        static void Main(string[] args)
        {
            Prepare();
        }

    }
}