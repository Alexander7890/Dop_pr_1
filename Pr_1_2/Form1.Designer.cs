namespace Pr_1_2
{
    partial class Form1
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form1));
            this.listBox1 = new System.Windows.Forms.ListBox();
            this.button1 = new System.Windows.Forms.Button();
            this.label1 = new System.Windows.Forms.Label();
            this.button3 = new System.Windows.Forms.Button();
            this.comboBoxStorageFormat = new System.Windows.Forms.ComboBox();
            this.comboBoxSearchAlgorithm = new System.Windows.Forms.ComboBox();
            this.comboBoxSignatureAlgorithm = new System.Windows.Forms.ComboBox();
            this.SuspendLayout();
            // 
            // listBox1
            // 
            this.listBox1.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(254)));
            this.listBox1.ItemHeight = 20;
            this.listBox1.Location = new System.Drawing.Point(284, 85);
            this.listBox1.Name = "listBox1";
            this.listBox1.Size = new System.Drawing.Size(752, 484);
            this.listBox1.TabIndex = 9;
            // 
            // button1
            // 
            this.button1.BackColor = System.Drawing.Color.Transparent;
            this.button1.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(254)));
            this.button1.Location = new System.Drawing.Point(28, 37);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(160, 56);
            this.button1.TabIndex = 5;
            this.button1.Text = "Вибрати файли";
            this.button1.UseVisualStyleBackColor = false;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.BackColor = System.Drawing.Color.Transparent;
            this.label1.Font = new System.Drawing.Font("Microsoft Sans Serif", 16F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(254)));
            this.label1.Location = new System.Drawing.Point(327, 37);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(654, 26);
            this.label1.TabIndex = 4;
            this.label1.Text = "Оберіть файли для додавання сигнатур натиснувши на кнопку";
            // 
            // button3
            // 
            this.button3.BackColor = System.Drawing.Color.Transparent;
            this.button3.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(254)));
            this.button3.ForeColor = System.Drawing.Color.Black;
            this.button3.Location = new System.Drawing.Point(28, 112);
            this.button3.Name = "button3";
            this.button3.Size = new System.Drawing.Size(160, 59);
            this.button3.TabIndex = 10;
            this.button3.Text = "Натисніть\r\nдля пошуку";
            this.button3.UseVisualStyleBackColor = false;
            this.button3.Click += new System.EventHandler(this.button3_Click_1);
            // 
            // comboBoxStorageFormat
            // 
            this.comboBoxStorageFormat.FormattingEnabled = true;
            this.comboBoxStorageFormat.Location = new System.Drawing.Point(28, 191);
            this.comboBoxStorageFormat.Name = "comboBoxStorageFormat";
            this.comboBoxStorageFormat.Size = new System.Drawing.Size(160, 21);
            this.comboBoxStorageFormat.TabIndex = 11;
            // 
            // comboBoxSearchAlgorithm
            // 
            this.comboBoxSearchAlgorithm.FormattingEnabled = true;
            this.comboBoxSearchAlgorithm.Location = new System.Drawing.Point(28, 281);
            this.comboBoxSearchAlgorithm.Name = "comboBoxSearchAlgorithm";
            this.comboBoxSearchAlgorithm.Size = new System.Drawing.Size(160, 21);
            this.comboBoxSearchAlgorithm.TabIndex = 12;
            // 
            // comboBoxSignatureAlgorithm
            // 
            this.comboBoxSignatureAlgorithm.FormattingEnabled = true;
            this.comboBoxSignatureAlgorithm.Location = new System.Drawing.Point(28, 390);
            this.comboBoxSignatureAlgorithm.Name = "comboBoxSignatureAlgorithm";
            this.comboBoxSignatureAlgorithm.Size = new System.Drawing.Size(160, 21);
            this.comboBoxSignatureAlgorithm.TabIndex = 13;
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.BackgroundImage = ((System.Drawing.Image)(resources.GetObject("$this.BackgroundImage")));
            this.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Stretch;
            this.ClientSize = new System.Drawing.Size(1048, 584);
            this.Controls.Add(this.comboBoxSignatureAlgorithm);
            this.Controls.Add(this.comboBoxSearchAlgorithm);
            this.Controls.Add(this.comboBoxStorageFormat);
            this.Controls.Add(this.button3);
            this.Controls.Add(this.listBox1);
            this.Controls.Add(this.button1);
            this.Controls.Add(this.label1);
            this.DoubleBuffered = true;
            this.Name = "Form1";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Form1";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.ListBox listBox1;
        private System.Windows.Forms.Button button1;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Button button3;
        private System.Windows.Forms.ComboBox comboBoxStorageFormat;
        private System.Windows.Forms.ComboBox comboBoxSearchAlgorithm;
        private System.Windows.Forms.ComboBox comboBoxSignatureAlgorithm;
    }
}

