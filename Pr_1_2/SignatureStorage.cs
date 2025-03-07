using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace Pr_1_2
{
    public static class SignatureStorage
    {
        private static string textFilePath = "signatures.txt";
        private static string binaryFilePath = "signatures.bin";

        public static void Save(string filePath, string signature, string format)
        {
            string hexSignature = NormalizeToHex(signature);

            if (format == "Binary")
            {
                SaveAsBinary(filePath, hexSignature);
            }
            else
            {
                SaveAsString(filePath, hexSignature);
            }
        }

        private static void SaveAsString(string filePath, string signature)
        {
            string entry = $"{filePath}:{signature}";
            File.AppendAllText(textFilePath, entry + Environment.NewLine);
        }

        private static void SaveAsBinary(string filePath, string signature)
        {
            using (FileStream fs = new FileStream(binaryFilePath, FileMode.Append, FileAccess.Write))
            using (BinaryWriter writer = new BinaryWriter(fs))
            {
                byte[] filePathBytes = Encoding.UTF8.GetBytes(filePath);
                byte[] signatureBytes = ConvertHexStringToByteArray(signature);

                writer.Write(filePathBytes.Length);
                writer.Write(filePathBytes);
                writer.Write(signatureBytes.Length);
                writer.Write(signatureBytes);
            }
        }

        public static void CheckFileForVirus(string filePath, string searchMethod)
        {
            List<string> detectedSignatures = new List<string>();
            List<string> algorithms = new List<string> { "SHA-1", "SHA-256", "SHA-512", "MD5", "CRC-32", "CRC-64", "Сума різниць 1х та 2х байтів", "XOR кожних 5-их байтів", "Сума по модулю 2^64" };

            foreach (string algorithm in algorithms)
            {
                string computedSignature = NormalizeToHex(SignatureCalculator.Calculate(filePath, algorithm));

                if (IsSignatureInDatabase(computedSignature, searchMethod, out string usedMethod))
                {
                    detectedSignatures.Add($"{algorithm}: {computedSignature}");
                }
            }

            if (detectedSignatures.Count > 0)
            {
                MessageBox.Show($"⚠️ Файл {Path.GetFileName(filePath)} інфікований!\nМетод пошуку: {searchMethod}\n\nЗбіги:\n" + string.Join("\n", detectedSignatures),
                                "Обнаружена загроза!", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            else
            {
                MessageBox.Show($"✔️ Файл {Path.GetFileName(filePath)} безпечний.\nМетод пошуку: {searchMethod}",
                                "Перевірка завершена", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        public static bool IsSignatureInDatabase(string signature, string searchMethod, out string usedMethod)
        {
            usedMethod = searchMethod;
            string hexSignature = NormalizeToHex(signature);

            bool foundInText = File.Exists(textFilePath) &&
                               File.ReadLines(textFilePath)
                                   .Select(line => line.Split(':').Last().Trim())
                                   .Contains(hexSignature);

            bool foundInBinary = File.Exists(binaryFilePath) && SearchInBinaryFile(hexSignature);

            return foundInText || foundInBinary;
        }

        private static bool SearchInBinaryFile(string targetSignature)
        {
            byte[] targetBytes = ConvertHexStringToByteArray(targetSignature);

            using (FileStream fs = new FileStream(binaryFilePath, FileMode.Open, FileAccess.Read))
            using (BinaryReader reader = new BinaryReader(fs))
            {
                while (fs.Position < fs.Length)
                {
                    int pathLength = reader.ReadInt32();
                    reader.ReadBytes(pathLength);

                    int sigLength = reader.ReadInt32();
                    byte[] signatureBytes = reader.ReadBytes(sigLength);

                    if (signatureBytes.SequenceEqual(targetBytes))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        public static void DeleteFromTextFile(string entry)
        {
            if (!File.Exists(textFilePath)) return;

            var lines = File.ReadAllLines(textFilePath).ToList();
            lines.RemoveAll(line => line.Equals(entry, StringComparison.OrdinalIgnoreCase));
            File.WriteAllLines(textFilePath, lines);
        }

        public static void DeleteFromBinaryFile(string entryToDelete)
        {
            if (!File.Exists(binaryFilePath)) return;

            List<byte[]> validRecords = new List<byte[]>();

            using (FileStream fs = new FileStream(binaryFilePath, FileMode.Open, FileAccess.Read))
            using (BinaryReader reader = new BinaryReader(fs))
            {
                while (fs.Position < fs.Length)
                {
                    long entryStart = fs.Position;

                    // Читаємо шлях до файлу
                    int pathLength = reader.ReadInt32();
                    byte[] pathBytes = reader.ReadBytes(pathLength);
                    string filePath = Encoding.UTF8.GetString(pathBytes);

                    // Читаємо сигнатуру
                    int signatureLength = reader.ReadInt32();
                    byte[] signatureBytes = reader.ReadBytes(signatureLength);
                    string signature = BitConverter.ToString(signatureBytes).Replace("-", "");

                    string currentEntry = $"{filePath}:{signature}";

                    // Якщо це не запис для видалення, зберігаємо його
                    if (!currentEntry.Equals(entryToDelete, StringComparison.OrdinalIgnoreCase))
                    {
                        using (MemoryStream ms = new MemoryStream())
                        using (BinaryWriter writer = new BinaryWriter(ms))
                        {
                            writer.Write(pathLength);
                            writer.Write(pathBytes);
                            writer.Write(signatureLength);
                            writer.Write(signatureBytes);
                            validRecords.Add(ms.ToArray());
                        }
                    }
                }
            }

            // Перезаписуємо файл без видаленого запису
            using (FileStream fs = new FileStream(binaryFilePath, FileMode.Create, FileAccess.Write))
            using (BinaryWriter writer = new BinaryWriter(fs))
            {
                foreach (var record in validRecords)
                {
                    writer.Write(record);
                }
            }
        }









        public static string NormalizeToHex(string input)
        {
            if (System.Text.RegularExpressions.Regex.IsMatch(input, @"\A\b[0-9A-Fa-f]+\b\Z") && input.Length % 2 == 0)
            {
                return input.ToUpper();
            }

            if (long.TryParse(input, out long numericValue))
            {
                return numericValue.ToString("X16");
            }

            return BitConverter.ToString(Encoding.UTF8.GetBytes(input)).Replace("-", "");
        }

        public static byte[] ConvertHexStringToByteArray(string hex)
        {
            if (hex.Length % 2 != 0)
                throw new ArgumentException("Некорректная HEX-строка");

            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }
    }
}