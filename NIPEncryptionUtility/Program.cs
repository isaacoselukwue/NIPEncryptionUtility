using DidiSoft.Pgp;
using NIPEncryptionUtility;
using Serilog;
using System.Text;

string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><FTAdviceDebitRequest><SessionID>999999220518062559519593639756</SessionID></FTAdviceDebitRequest>";
string encryptedText = Encrypt(xml);

Console.WriteLine("Xml is: {0}", encryptedText);

Console.ReadLine();

string decryptedText = Decrypt(encryptedText);

Console.WriteLine("Decrypted XML is: {0}", decryptedText);

Console.ReadLine();


string Decrypt(string hex_response)
{
    try
    {
        string[] decryptedVal = hex_response.Split(";", StringSplitOptions.RemoveEmptyEntries);
        StringBuilder sb = new();
        foreach (string decrypted in decryptedVal)
        {
            if (!string.IsNullOrEmpty(decrypted))
                sb.Append(ProcessDecryption(decrypted));
        }
        string response_output = sb.ToString();
        Log.Information($"Decrypted value PGP {response_output} for {hex_response}");
        return response_output;
    }
    catch (Exception ex)
    {
        Log.Error(ex, $"Error occured while decrypting {hex_response}");
        return "";
    }
}
string ProcessDecryption(string hex_response)
{
    string? bank_private_key_password = "YourPrivateKeyPassword";
    string? bank_private_key_file = Path.Combine(Directory.GetCurrentDirectory(), "private.key");
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
string Encrypt(string request)
{
    StringBuilder response = new();
    List<string> strings = SplitString(request, 1024).ToList();
    foreach (string s in strings)
    {
        response.Append(ProcessEncryption(s));
    }
    Log.Information($"Encrypted value PGP {response} for {request}");
    return response.ToString();
}
static IEnumerable<string> SplitString(string text, int size)
{
    for (int i = 0; i < text.Length; i += size)
    {
        yield return text.Substring(i, Math.Min(size, text.Length - i));
    }
}
string ProcessEncryption(string request)
{
    try
    {
        Log.Information($"Raw Request {request}");
        byte[]? input_byte = null;
        string input_hex = ""; string? encrypt_val = "";
        MemoryStream? input_stream = null;
        MemoryStream? output_stream = null;
        string? nibss_public_key_file = Path.Combine(Directory.GetCurrentDirectory(), "public.key");
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