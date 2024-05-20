Hello,

To use this package to encrypt call the following method:

string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><FTAdviceDebitRequest><SessionID>999999220518062559519593639756</SessionID></FTAdviceDebitRequest>";
string encryptedText = SSM.Encrypt(xml, "public.key");
here public.key is the path to nibss provided key
string decryptedText = SSM.Decrypt(encryptedText, "YourPassword", "private.key");
YourPassword refers to the password used to generate the key and private.key is your personal private key
