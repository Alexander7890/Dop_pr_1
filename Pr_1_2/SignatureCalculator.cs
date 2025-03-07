using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.IO.Hashing;

namespace Pr_1_2
{
    public static class SignatureCalculator
    {
        public static void CalculateAndSave(string filePath, string algorithm, string format)
        {
            string signature = Calculate(filePath, algorithm);
            SignatureStorage.Save(Path.GetFileName(filePath), signature, format);
        }

        public static string Calculate(string filePath, string algorithm)
        {
            switch (algorithm)
            {
                case "Сума по модулю 2^64":
                    return SumMod64(filePath).ToString();
                case "XOR кожних 5-их байтів":
                    return ComputeXOREvery5thByte(filePath).ToString("X16"); // Вивід у HEX-форматі
                case "Сума різниць 1х та 2х байтів":
                    return ComputeSumDifferences(filePath).ToString();
                case "SHA-1":
                    return ComputeSHA1(filePath);
                case "SHA-256":
                    return ComputeSHA256(filePath);
                case "SHA-384":
                    return ComputeSHA384(filePath);
                case "SHA-512":
                    return ComputeSHA512(filePath);
                case "RIPE-MD":
                    return ComputeRIPEMD160(filePath);
                case "CRC-32":
                    return ComputeCRC32(filePath);
                case "CRC-64":
                    return ComputeCRC64(filePath);
                case "MD5":
                    return ComputeMD5(filePath);
                default:
                    throw new ArgumentException($"Невідомий алгоритм: {algorithm}");
            }
        }

        // --- Сума по модулю 2^64 ---
        private static ulong SumMod64(string filePath)
        {
            ulong sum = 0;
            try
            {
                byte[] fileBytes = File.ReadAllBytes(filePath);
                foreach (byte b in fileBytes)
                {
                    sum = (sum + b) % ulong.MaxValue;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Помилка: {ex.Message}");
            }
            return sum;
        }

        // --- XOR кожних 5-их байтів ---
        private static ulong ComputeXOREvery5thByte(string filePath)
        {
            ulong result = 0;
            try
            {
                byte[] fileBytes = File.ReadAllBytes(filePath);

                if (fileBytes.Length < 5)
                    return 0; // Якщо у файлі менше 5 байтів, повертаємо 0

                for (int i = 4; i < fileBytes.Length; i += 5)
                {
                    result ^= (ulong)fileBytes[i] << ((i % 8) * 8);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Помилка: {ex.Message}");
            }
            return result;
        }


        // --- Сума різниць 1х та 2х байтів ---
        private static long ComputeSumDifferences(string filePath)
        {
            long sum = 0;
            try
            {
                byte[] fileBytes = File.ReadAllBytes(filePath);
                for (int i = 2; i < fileBytes.Length; i++)
                {
                    sum += Math.Abs(fileBytes[i] - fileBytes[i - 1]) + Math.Abs(fileBytes[i] - fileBytes[i - 2]);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Помилка: {ex.Message}");
            }
            return sum;
        }

        // --- SHA-1 ---
        private static string ComputeSHA1(string filePath)
        {
            using (SHA1 sha1 = SHA1.Create())
            {
                return ComputeHash(sha1, filePath);
            }
        }

        // --- SHA-256 ---
        private static string ComputeSHA256(string filePath)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return ComputeHash(sha256, filePath);
            }
        }

        // --- SHA-384 ---
        private static string ComputeSHA384(string filePath)
        {
            using (SHA384 sha384 = SHA384.Create())
            {
                return ComputeHash(sha384, filePath);
            }
        }

        // --- SHA-512 ---
        private static string ComputeSHA512(string filePath)
        {
            using (SHA512 sha512 = SHA512.Create())
            {
                return ComputeHash(sha512, filePath);
            }
        }

        // --- RIPEMD-160 ---
        private static string ComputeRIPEMD160(string filePath)
        {
            using (FileStream stream = File.OpenRead(filePath))
            using (RIPEMD160 ripemd160 = RIPEMD160.Create())
            {
                byte[] hashBytes = ripemd160.ComputeHash(stream);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            }
        }

        // --- CRC-32 ---
        private static string ComputeCRC32(string filePath)
        {
            try
            {
                using (FileStream stream = File.OpenRead(filePath))
                {
                    Crc32 crc32 = new Crc32();
                    crc32.Append(stream);
                    byte[] hashBytes = crc32.GetCurrentHash();
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                }
            }
            catch (Exception ex)
            {
                return $"Помилка: {ex.Message}";
            }
        }

        // --- CRC-64 ---
        private static string ComputeCRC64(string filePath)
        {
            try
            {
                using (FileStream stream = File.OpenRead(filePath))
                {
                    Crc64 crc64 = new Crc64();
                    crc64.Append(stream);
                    byte[] hashBytes = crc64.GetCurrentHash();
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                }
            }
            catch (Exception ex)
            {
                return $"Помилка: {ex.Message}";
            }
        }

        // --- MD5 ---
        private static string ComputeMD5(string filePath)
        {
            try
            {
                using (MD5 md5 = MD5.Create())
                using (FileStream stream = File.OpenRead(filePath))
                {
                    byte[] hashBytes = md5.ComputeHash(stream);
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                }
            }
            catch (Exception ex)
            {
                return $"Помилка: {ex.Message}";
            }
        }

        // --- Метод для обчислення хешу з HashAlgorithm ---
        private static string ComputeHash(HashAlgorithm algorithm, string filePath)
        {
            try
            {
                using (FileStream fs = File.OpenRead(filePath))
                {
                    byte[] hashBytes = algorithm.ComputeHash(fs);
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                }
            }
            catch (Exception ex)
            {
                return $"Помилка: {ex.Message}";
            }
        }
    }
}
