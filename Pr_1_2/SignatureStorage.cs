using System;
using System.Collections.Generic;
using System.Diagnostics;
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
        // Метод, який зберігає сигнатуру
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
        // Метод, який зберігає сигнатуру у текстовому файлі
        private static void SaveAsString(string filePath, string signature)
        {
            string entry = $"{filePath}:{signature}";
            File.AppendAllText(textFilePath, entry + Environment.NewLine);
        }
        // Метод, який зберігає сигнатуру у бінарному файлі
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
        // Метод, який перевіряє файл на віруси
        public static void CheckFileForVirus(string filePath, string searchMethod)
        {
            List<string> detectedSignatures = new List<string>();
            List<string> algorithms = new List<string> { "SHA-1", "SHA-256", "SHA-384", "SHA-512", "MD5", "CRC-32", "CRC-64", "Сума різниць 1х та 2х байтів", "XOR кожних 5-их байтів", "Сума по модулю 2^64" };

            foreach (string algorithm in algorithms)
            {
                string computedSignature = NormalizeToHex(SignatureCalculator.Calculate(filePath, algorithm));
                if (IsSignatureInDatabase(computedSignature, searchMethod, out string usedMethod, out double elapsedTime))
                {
                    detectedSignatures.Add($"{algorithm}: {computedSignature} (Час пошуку: {elapsedTime:F10} мс)");
                }
            }

            MessageBox.Show(detectedSignatures.Count > 0 ? $"⚠️ Файл {Path.GetFileName(filePath)} інфікований!\nМетод пошуку: {searchMethod}\n\nЗбіги:\n" + string.Join("\n", detectedSignatures) : $"✔️ Файл {Path.GetFileName(filePath)} безпечний.\nМетод пошуку: {searchMethod}", "Результат", MessageBoxButtons.OK, detectedSignatures.Count > 0 ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
        }
        
        public static bool IsSignatureInDatabase(string signature, string searchMethod, out string usedMethod)
        {
            return IsSignatureInDatabase(signature, searchMethod, out usedMethod, out _);
        }

        //Метод, який перевіряє, чи є сигнатура в базі даних
        public static bool IsSignatureInDatabase(string signature, string searchMethod, out string usedMethod, out double elapsedTime)
        {
            usedMethod = searchMethod;
            string hexSignature = NormalizeToHex(signature);
            bool found = false;
            Stopwatch stopwatch = Stopwatch.StartNew();

            if (File.Exists(textFilePath))
            {
                List<string> signatures = File.ReadLines(textFilePath).Select(line => line.Split(':').Last().Trim()).ToList();
                switch (searchMethod)
                {
                    case "Лінійний пошук":
                        found = signatures.Contains(hexSignature);
                        break;
                    case "Лінійний пошук з бар'єром":
                        found = LinearSearchWithBarrier(signatures, hexSignature);
                        break;
                    case "Двійковий пошук":
                        signatures.Sort();
                        found = signatures.BinarySearch(hexSignature) >= 0;
                        break;
                }
            }

            if (!found && File.Exists(binaryFilePath))
            {
                found = SearchInBinaryFile(hexSignature);
            }

            stopwatch.Stop();
            elapsedTime = stopwatch.Elapsed.TotalMilliseconds;
            return found;
        }
        //Метод, який виконує лінійний пошук з бар'єром
        private static bool LinearSearchWithBarrier(List<string> list, string target)
        {
            list.Add(target);
            int i = 0;
            while (list[i] != target)
            {
                i++;
            }
            list.RemoveAt(list.Count - 1);
            return i < list.Count;
        }
        //Метод, який виконує пошук у бінарному файлі
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
                    if (signatureBytes.SequenceEqual(targetBytes)) return true;
                }
            }
            return false;
        }
        // Метод, який нормалізує вхідну строку до шістнадцяткового формату
        public static string NormalizeToHex(string input)
        {
            if (System.Text.RegularExpressions.Regex.IsMatch(input, "\\A\\b[0-9A-Fa-f]+\\b\\Z") && input.Length % 2 == 0)
            {
                return input.ToUpper();
            }
            if (long.TryParse(input, out long numericValue))
            {
                return numericValue.ToString("X16");
            }
            return BitConverter.ToString(Encoding.UTF8.GetBytes(input)).Replace("-", "");
        }
        // Метод, який конвертує шістнадцятковий рядок у масив байтів
        public static byte[] ConvertHexStringToByteArray(string hex)
        {
            if (hex.Length % 2 != 0) throw new ArgumentException("Некорректная HEX-строка");
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