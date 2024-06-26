﻿using System.Text;

namespace NIPUtility;
internal class Hex
{
    public static byte[] HexWithFix(string hex)
    {
        byte[] raw = null;
        try
        {
            // hex = hex.Replace(";", "");
            raw = new byte[hex.Length / 2];
            for (int i = 0; i < raw.Length; i++)
            {
                raw[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
        }
        catch (Exception)
        {

        }
        return raw;
    }

    public static byte[] GetBytes(string data, out int discarded)
    {
        discarded = 1;
        int c;
        List<byte> result = [];

        try
        {
            using MemoryStream ms = new();
            using StreamWriter sw = new(ms);
            sw.Write(data);
            sw.Flush();
            ms.Position = 0;
            using StreamReader sr = new(ms);

            StringBuilder number = new();

            while ((c = sr.Read()) > 0)
            {
                if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
                {
                    number.Append((char)c);

                    if (number.Length >= 2)
                    {
                        result.Add(Convert.ToByte(number.ToString(), 16));
                        number.Length = 0;
                    }
                }
            }
        }
        catch (Exception)
        {

        }
        return [.. result];
    }

    public static int GetByteCount(string hexString)
    {
        int numHexChars = 0;
        char c;
        // remove all none A-F, 0-9, characters
        for (int i = 0; i < hexString.Length; i++)
        {
            c = hexString[i];
            if (IsHexDigit(c))
                numHexChars++;
        }
        // if odd number of characters, discard last character
        if (numHexChars % 2 != 0)
        {
            numHexChars--;
        }
        return numHexChars / 2; // 2 characters per byte
    }
    /// <summary>
    /// Creates a byte array from the hexadecimal string. Each two characters are combined
    /// to create one byte. First two hexadecimal characters become first byte in returned array.
    /// Non-hexadecimal characters are ignored. 
    /// </summary>
    /// <param name="hexString">string to convert to byte array</param>
    /// <param name="discarded">number of characters in string ignored</param>
    /// <returns>byte array, in the same left-to-right order as the hexString</returns>
    public static byte[] GetBytes_old(string hexString, out int discarded)
    {
        discarded = 0;
        string newString = "";
        char c;
        // remove all none A-F, 0-9, characters
        for (int i = 0; i < hexString.Length; i++)
        {
            c = hexString[i];
            if (IsHexDigit(c))
                newString += c;
            else
                discarded++;
        }
        // if odd number of characters, discard last character
        if (newString.Length % 2 != 0)
        {
            discarded++;
            newString = newString[..^1];
        }

        int byteLength = newString.Length / 2;
        byte[] bytes = new byte[byteLength];
        string hex;
        int j = 0;
        for (int i = 0; i < bytes.Length; i++)
        {
            hex = new String(new Char[] { newString[j], newString[j + 1] });
            bytes[i] = HexToByte(hex);
            j += 2;
        }
        return bytes;
    }
    public static string ToString(byte[] bytes)
    {
        string hexString = "";
        for (int i = 0; i < bytes.Length; i++)
        {
            hexString += bytes[i].ToString("X2");
        }
        return hexString;
    }
    /// <summary>
    /// Determines if given string is in proper hexadecimal string format
    /// </summary>
    /// <param name="hexString"></param>
    /// <returns></returns>
    public static bool InHexFormat(string hexString)
    {
        bool hexFormat = true;

        foreach (char digit in hexString)
        {
            if (!IsHexDigit(digit))
            {
                hexFormat = false;
                break;
            }
        }
        return hexFormat;
    }

    /// <summary>
    /// Returns true is c is a hexadecimal digit (A-F, a-f, 0-9)
    /// </summary>
    /// <param name="c">Character to test</param>
    /// <returns>true if hex digit, false if not</returns>
    public static bool IsHexDigit(Char c)
    {
        int numChar;
        int numA = Convert.ToInt32('A');
        int num1 = Convert.ToInt32('0');
        c = Char.ToUpper(c);
        numChar = Convert.ToInt32(c);
        if (numChar >= numA && numChar < (numA + 6))
            return true;
        if (numChar >= num1 && numChar < (num1 + 10))
            return true;
        return false;
    }
    /// <summary>
    /// Converts 1 or 2 character string into equivalant byte value
    /// </summary>
    /// <param name="hex">1 or 2 character string</param>
    /// <returns>byte</returns>
    private static byte HexToByte(string hex)
    {
        if (hex.Length > 2 || hex.Length <= 0)
            throw new ArgumentException("hex must be 1 or 2 characters in length");
        byte newByte = byte.Parse(hex, System.Globalization.NumberStyles.HexNumber);
        return newByte;
    }
}