using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows.Forms;
using System.Text;


namespace Pr_1_2
{
    public partial class Form1 : Form
    {
        private static string textFilePath = "signatures.txt";
        private static string binaryFilePath = "signatures.bin";

        public Form1()
        {
            InitializeComponent();
            LoadDictionary();
            InitializeContextMenu();
            InitializeComboBoxes();
        }

        private void InitializeComboBoxes()
        {
            comboBoxStorageFormat.Items.AddRange(new string[] { "Binary", "String" });
            comboBoxSearchAlgorithm.Items.AddRange(new string[] { "Лінійний пошук", "Лінійний пошук з бар'єром", "Двійковий пошук" });
            comboBoxSignatureAlgorithm.Items.AddRange(new string[]
            {
                "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "RIPE-MD", "CRC-64", "CRC-32",
                "Сума по модулю 2^64", "XOR кожних 5-их байтів", "Сума різниць 1х та 2х байтів"
            });
                        // Встановлення значень за замовчуванням
            comboBoxStorageFormat.SelectedIndex = 1;  // String
            comboBoxSearchAlgorithm.SelectedIndex = 0;  // Лінійний пошук
            comboBoxSignatureAlgorithm.SelectedIndex = 8;  // Сума по модулю 2^64

        }

        // Завантаження словника у listBox з текстового та бінарного файлу
        private void LoadDictionary()
        {
            listBox1.Items.Clear();

            // Читаємо всі рядки з текстового файлу (String)
            if (File.Exists(textFilePath))
            {
                var lines = File.ReadAllLines(textFilePath);
                foreach (var line in lines)
                {
                    if (!string.IsNullOrWhiteSpace(line))
                        listBox1.Items.Add(line); // Додаємо кожен рядок окремо
                }
            }

            // Читаємо всі записи з бінарного файлу (Binary)
            if (File.Exists(binaryFilePath))
            {
                using (FileStream fs = new FileStream(binaryFilePath, FileMode.Open, FileAccess.Read))
                using (BinaryReader reader = new BinaryReader(fs))
                {
                    while (fs.Position < fs.Length)
                    {
                        try
                        {
                            int pathLength = reader.ReadInt32();
                            string filePath = Encoding.UTF8.GetString(reader.ReadBytes(pathLength));

                            int signatureLength = reader.ReadInt32();
                            string signature;

                            if (signatureLength == sizeof(ulong)) // Якщо це число, конвертуємо
                            {
                                ulong signatureValue = reader.ReadUInt64();
                                signature = signatureValue.ToString("X16"); // Виправлення: виводимо у вигляді 16-значного HEX
                            }

                            else
                            {
                                byte[] signatureBytes = reader.ReadBytes(signatureLength);
                                signature = BitConverter.ToString(signatureBytes).Replace("-", "").ToLower();
                            }

                            // Додаємо новий запис в listBox окремим рядком
                            listBox1.Items.Add($"{filePath}:{signature}");
                        }
                        catch (Exception ex)
                        {
                            MessageBox.Show($"Помилка при читанні бінарного файлу:\n{ex.Message}",
                                            "Помилка", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }
                    }
                }
            }
        }


        // Додавання файлу в список
        private void button1_Click(object sender, EventArgs e)
        {
            if (comboBoxStorageFormat.SelectedItem == null || comboBoxSignatureAlgorithm.SelectedItem == null)
            {
                MessageBox.Show("Будь ласка, виберіть параметри у списках!", "Помилка", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            OpenFileDialog openFileDialog = new OpenFileDialog { Multiselect = true };
            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                string format = comboBoxStorageFormat.SelectedItem.ToString();
                string algorithm = comboBoxSignatureAlgorithm.SelectedItem.ToString();

                foreach (string file in openFileDialog.FileNames)
                {
                    string signature = SignatureCalculator.Calculate(file, algorithm);
                    string hexSignature = SignatureStorage.NormalizeToHex(signature);
                    string entry = $"{file}:{hexSignature}";

                    if (!listBox1.Items.Contains(entry))
                    {
                        listBox1.Items.Add(entry);

                        // Перевіряємо, чи запис вже є у файлі перед збереженням
                        if (!SignatureStorage.IsSignatureInDatabase(hexSignature, "Перевірка перед збереженням", out _))
                        {
                            SignatureStorage.Save(file, signature, format);
                        }
                        else
                        {
                            MessageBox.Show("Такий запис вже існує у файлі!", "Увага", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        }
                    }
                    else
                    {
                        MessageBox.Show("Такий запис вже існує у списку!", "Увага", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }
                }

                LoadDictionary(); // Оновлення списку після додавання файлів
            }
        }


        private void button3_Click_1(object sender, EventArgs e)
        {
            if (comboBoxSearchAlgorithm.SelectedItem == null)
            {
                MessageBox.Show("Оберіть алгоритм пошуку!", "Помилка", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            OpenFileDialog openFileDialog = new OpenFileDialog { Multiselect = true };

            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                string searchAlgorithm = comboBoxSearchAlgorithm.SelectedItem.ToString();

                MessageBox.Show($"Обраний алгоритм: {searchAlgorithm}"); // Перевірка вибору алгоритму

                foreach (string file in openFileDialog.FileNames)
                {
                    SignatureStorage.CheckFileForVirus(file, searchAlgorithm);
                }
            }
        }

        private void InitializeContextMenu()
        {
            ContextMenuStrip contextMenu = new ContextMenuStrip();

            // Пункт для видалення
            var deleteItem = new ToolStripMenuItem("Видалити запис");
            deleteItem.Click += DeleteSelectedItem;

            // Пункт для копіювання
            var copyItem = new ToolStripMenuItem("Копіювати сигнатуру");
            copyItem.Click += CopySelectedItem;

            //Додавання пунктів в меню
            contextMenu.Items.Add(deleteItem);
            contextMenu.Items.Add(copyItem);
            listBox1.ContextMenuStrip = contextMenu;
        }

        private void DeleteSelectedItem(object sender, EventArgs e)
        {
            if (listBox1.SelectedItem != null)
            {
                string selectedEntry = listBox1.SelectedItem.ToString().Trim();

                // Розділяємо запис "filePath:signature" на дві частини
                string[] parts = selectedEntry.Split(':');
                if (parts.Length < 2)
                {
                    MessageBox.Show("Невірний формат запису!", "Помилка", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                string filePath = parts[0].Trim(); // Видаляємо зайві пробіли

                // Видаляємо з ListBox
                listBox1.Items.Remove(selectedEntry);

                // Видаляємо з текстового файлу
                SignatureStorage.DeleteFromTextFile(selectedEntry);

                // Видаляємо з бінарного файлу тільки за filePath
                SignatureStorage.DeleteFromBinaryFile(selectedEntry);

                MessageBox.Show("Запис успішно видалено!", "Видалення", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }



        private void CopySelectedItem(object sender, EventArgs e)
        {
            if (listBox1.SelectedItem != null)
            {
                // Отримуємо вибрану запис з listBox
                string selectedEntry = listBox1.SelectedItem.ToString();

                // Витягти сигнатуру з запису (припускаємо, що сигнатура завжди після двокрапки)
                int signatureStartIndex = selectedEntry.LastIndexOf("🔑 Сигнатура:") + "🔑 Сигнатура:".Length;
                string signature = selectedEntry.Substring(signatureStartIndex).Trim();

                // Копіюємо сигнатуру в буфер обміну
                Clipboard.SetText(signature);

                MessageBox.Show("Сигнатура скопійована в буфер обміну!", "Копіювання", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                MessageBox.Show("Будь ласка, виберіть запис для копіювання!", "Помилка", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }
    }
}