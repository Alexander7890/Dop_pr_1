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
        // Шляхи до файлів зі збереженими сигнатурами
        private static string textFilePath = "signatures.txt";
        private static string binaryFilePath = "signatures.bin";

        // Зберігає сигнатуру в файлі
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
        // Зберігає сигнатуру в текстовому файлі
        private static void SaveAsString(string filePath, string signature)
        {
            string entry = $"{filePath}:{signature}";
            File.AppendAllText(textFilePath, entry + Environment.NewLine);
        }
        // Зберігає сигнатуру в бінарному файлі
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
        // Перевіряє файл на віруси
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
        // Перевіряє, чи є сигнатура в базі даних
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
        // Пошук сигнатури в бінарному файлі
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

        // Нормалізує вхідну строку до HEX-формату
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
        // Перетворює HEX-строку в масив байтів
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

        // Видаляє сигнатуру з текстового файлу
        public static void DeleteFromTextFile(string entryToDelete)
        {
            if (!File.Exists(textFilePath)) return;

            var lines = File.ReadAllLines(textFilePath).ToList();
            lines.RemoveAll(line => line.Contains(entryToDelete));

            File.WriteAllLines(textFilePath, lines);
        }

        // Видаляє сигнатуру з бінарного файлу
        public static void DeleteFromBinaryFile(string entryToDelete)
        {
            if (!File.Exists(binaryFilePath)) return;

            List<byte> updatedData = new List<byte>();

            using (FileStream fs = new FileStream(binaryFilePath, FileMode.Open, FileAccess.Read))
            using (BinaryReader reader = new BinaryReader(fs))
            {
                while (fs.Position < fs.Length)
                {
                    // Читаємо довжину та шлях файлу
                    int filePathLength = reader.ReadInt32();
                    byte[] filePathBytes = reader.ReadBytes(filePathLength);
                    string filePath = Encoding.UTF8.GetString(filePathBytes);

                    // Читаємо довжину та значення сигнатури
                    int signatureLength = reader.ReadInt32();
                    byte[] signatureBytes = reader.ReadBytes(signatureLength);
                    string signatureHex = BitConverter.ToString(signatureBytes).Replace("-", "");

                    // Формуємо рядковий запис для перевірки
                    string currentEntry = $"{filePath}:{signatureHex}";

                    // Якщо запис не збігається з entryToDelete, зберігаємо його
                    if (!currentEntry.Equals(entryToDelete, StringComparison.OrdinalIgnoreCase))
                    {
                        updatedData.AddRange(BitConverter.GetBytes(filePathLength));
                        updatedData.AddRange(filePathBytes);
                        updatedData.AddRange(BitConverter.GetBytes(signatureLength));
                        updatedData.AddRange(signatureBytes);
                    }
                }
            }

            // Якщо всі записи видалені, очищуємо файл
            if (updatedData.Count == 0)
            {
                File.Delete(binaryFilePath);
            }
            else
            {
                File.WriteAllBytes(binaryFilePath, updatedData.ToArray());
            }
        }


    }
}