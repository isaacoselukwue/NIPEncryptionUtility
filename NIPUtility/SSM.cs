using DidiSoft.Pgp;
using Serilog;
using System.Text;

namespace NIPUtility;

public class SSM
{
    public static string Decrypt(string encryptedResponse, string password, string privateKeyPath)
    {
        try
        {
            string[] decryptedVal = encryptedResponse.Split(";", StringSplitOptions.RemoveEmptyEntries);
            StringBuilder sb = new();
            foreach (string decrypted in decryptedVal)
            {
                if (!string.IsNullOrEmpty(decrypted))
                    sb.Append(ProcessDecryption(decrypted, password, privateKeyPath));
            }
            string response_output = sb.ToString();
            Log.Information($"Decrypted value PGP {response_output} for {encryptedResponse}");
            return response_output;
        }
        catch (Exception ex)
        {
            Log.Error(ex, $"Error occured while decrypting {encryptedResponse}");
            return "";
        }
    }
    private static string ProcessDecryption(string hex_response, string bank_private_key_password, string bank_private_key_file)
    {
        byte[] byte_response = Hex.GetBytes(hex_response, out _);
        MemoryStream? response_output_stream = new();
        Stream? response_stream = new MemoryStream(byte_response);
        Stream key_stream = new FileStream(bank_private_key_file, FileMode.Open, FileAccess.Read);
        PGPLib pgp = new();
        pgp.DecryptStream(response_stream, key_stream, bank_private_key_password, response_output_stream);
        byte[] byte_response_output = response_output_stream.ToArray();
        string response_output = new System.Text.UTF8Encoding().GetString(byte_response_output);
        return response_output;
    }
    public static string Encrypt(string request, string publicKeyPath)
    {
        StringBuilder response = new();
        List<string> strings = SplitString(request, 1024).ToList();
        foreach (string s in strings)
        {
            response.Append(ProcessEncryption(s, publicKeyPath));
        }
        Log.Information($"Encrypted value PGP {response} for {request}");
        return response.ToString();
    }
    private static IEnumerable<string> SplitString(string text, int size)
    {
        for (int i = 0; i < text.Length; i += size)
        {
            yield return text.Substring(i, Math.Min(size, text.Length - i));
        }
    }
    private static string ProcessEncryption(string request, string nibss_public_key_file)
    {
        try
        {
            Log.Information($"Raw Request {request}");
            byte[]? input_byte = null;
            string input_hex = ""; string? encrypt_val = "";
            MemoryStream? input_stream = null;
            MemoryStream? output_stream = null;
            PGPLib pgp = new();
            input_stream = new MemoryStream(new System.Text.UTF8Encoding().GetBytes(request));
            output_stream = new MemoryStream();
            pgp.EncryptStream(input_stream, new FileInfo(nibss_public_key_file), output_stream, false);
            try
            {
                input_byte = output_stream.ToArray();
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error encrypting");
            }
            input_hex = Hex.ToString(input_byte);
            encrypt_val = input_hex + ";";
            Log.Information("Encrypted value " + encrypt_val);
            return encrypt_val;
        }
        catch (Exception ex)
        {
            Log.Error(ex, $"Error occured while decrypting {request}");
            return "";
        }
    }
}
