using NIPUtility;

string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><FTAdviceDebitRequest><SessionID>999999220518062559519593639756</SessionID></FTAdviceDebitRequest>";
string nibss_public_key_file = Path.Combine(Directory.GetCurrentDirectory(), "public.key");
string encryptedText = SSM.Encrypt(xml, nibss_public_key_file);

Console.WriteLine("Xml is: {0}", encryptedText);

Console.ReadLine();
string bank_private_key_password = "YourPrivateKeyPassword";
string bank_private_key_file = Path.Combine(Directory.GetCurrentDirectory(), "private.key");
string decryptedText = SSM.Decrypt(encryptedText, bank_private_key_password, bank_private_key_file);

Console.WriteLine("Decrypted XML is: {0}", decryptedText);

Console.ReadLine();