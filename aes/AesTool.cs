using System.Security.Cryptography;

public class AesTool {
	public static Aes crypto = Aes.Create();
	
	public static void Print(Aes a) {
		Console.Write("Generated AES-" + crypto.KeySize + " Properties:\nKey:\t");
		foreach (byte b in a.Key)
			Console.Write("{0:X2}", b);
		Console.Write("\nIV:\t");
		foreach (byte b in a.IV)
			Console.Write("{0:X2}", b);
	}
	
	public static byte[] StringToByteArray(string str) {
		if (str.Length == 0)
			throw new ArgumentException("Passed empty string");
		if (str.Length % 2 == 1)
			throw new FormatException("Passed not full-byte format");
		
		int len = str.Length;
		len /= 2;
		byte[] res = new byte[len];
		try {
			for (int i = 0; i < len; i++)
				res[i] = Convert.ToByte(str.Substring(i * 2, 2), 16);
		} catch (FormatException) {
			throw new FormatException("String: " + str + " is not parsable to HEX format");
		}
		return res;
	}
	
	public static void Setup(byte[] key, byte[] iv, string src, string dest) {
		crypto.Key = key;
		crypto.IV  = iv;
		if (src.Length == 0)
			throw new ArgumentException("Passed empty string");
		if (dest.Length == 0)
			throw new ArgumentException("Passed empty string");
	}
	
	public static void Encrypt(byte[] key, byte[] iv, string src, string dest) {
		Setup(key, iv, src, dest);
		ICryptoTransform encryptor = crypto.CreateEncryptor();
		try {
			byte[] input  = File.ReadAllBytes(src);
			byte[] output = encryptor.TransformFinalBlock(input, 0, input.Length);
			File.WriteAllBytes(dest, output);
		} catch (Exception e) {
			throw new Exception(e.Message);
		}
		Console.WriteLine("Success! Encrypted into " + dest + " file");
	}
	
	public static void Decrypt(byte[] key, byte[] iv, string src, string dest) {
		Setup(key, iv, src, dest);
		ICryptoTransform decryptor = crypto.CreateDecryptor();
		try {
			byte[] input  = File.ReadAllBytes(src);
			byte[] output = decryptor.TransformFinalBlock(input, 0, input.Length);
			File.WriteAllBytes(dest, output);
		} catch (Exception e) {
			throw new Exception(e.Message);
		}
		Console.WriteLine("Success! Decrypted into " + dest + " file");
	}
	
	public static void Main(string[] args) {
		if (args.Length == 2 && args[0].ToLower() == "keygen") {
			try {
				crypto.KeySize = Convert.ToInt32(args[1]);
			} catch (Exception e) {
				Console.WriteLine(e.Message);
				return;
			}
			Print(crypto);
		}
		else if (args.Length >= 5) {
			try {
				if (args[0].ToLower() == "encrypt") {
					Encrypt(StringToByteArray(args[1]), StringToByteArray(args[2]), args[3], args[4]);
				}
				else if (args[0].ToLower() == "decrypt") {
					Decrypt(StringToByteArray(args[1]), StringToByteArray(args[2]), args[3], args[4]);
				}
				else {
					Console.WriteLine("Unknown instruction. Arguments:");
					Console.WriteLine("<decrypt>/<encrypt> <KEY> <IV> <SRC_FILE> <DST_FILE>");
				}
			} catch (Exception e) {
				Console.WriteLine(e.Message);
				return;
			}
		}
		else {
			Console.WriteLine("Arguments:");
			Console.WriteLine("decrypt/encrypt [KEY] [IV] [SRC_FILE] [DST_FILE]");
			Console.WriteLine("keygen [128/192/256]");
		}
	}
}
