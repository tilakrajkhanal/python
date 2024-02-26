import sys
import string
import secrets
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QVBoxLayout, QWidget, QMessageBox, QTextEdit, QHBoxLayout,\
QFileDialog
from password_strength import PasswordPolicy
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64

class PasswordStrengthChecker(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Strength Checker")
        self.init_ui()

    def init_ui(self):
        # Create the password label and entry
        self.label_password = QLabel("Password:")
        self.entry_password = QLineEdit()

        # Connect the textChanged signal of the password entry to save_password slot
        self.entry_password.textChanged.connect(self.save_password)

        # Create the button to check password strength
        self.button_check = QPushButton("Check Strength")
        self.button_check.clicked.connect(self.check_password_strength)

        # Create the label to display password strength
        self.label_strength = QLabel()

        # Create the button to generate a strong password
        self.button_generate_strong_password = QPushButton("Generate Strong Password")
        self.button_generate_strong_password.clicked.connect(self.generate_strong_password)

        # Create the button to encrypt data
        self.button_encrypt = QPushButton("Encrypt Data")
        self.button_encrypt.clicked.connect(self.encrypt_data)

        # Create the button to decrypt data
        self.button_decrypt = QPushButton("Decrypt Data")
        self.button_decrypt.clicked.connect(self.decrypt_data)

        # Create the label and text field for entering data to be encrypted
        self.label_data_to_encrypt = QLabel("Data to Encrypt:")
        self.entry_data_to_encrypt = QLineEdit()

        # Create the label and text field for displaying encrypted data
        self.label_encrypted_data = QLabel("Encrypted Data:")
        self.text_encrypted_data = QTextEdit()
        self.text_encrypted_data.setReadOnly(True)

        # Create the label and text field for entering data to be decrypted
        self.label_data_to_decrypt = QLabel("Data to Decrypt:")
        self.entry_data_to_decrypt = QLineEdit()

        # Create the label and text field for displaying decrypted data
        self.label_decrypted_data = QLabel("Decrypted Data:")
        self.text_decrypted_data = QTextEdit()
        self.text_decrypted_data.setReadOnly(True)

        # Create the button to save encrypted data
        self.button_save_encrypted_data = QPushButton("Save Encrypted Data")
        self.button_save_encrypted_data.clicked.connect(self.save_encrypted_data)

        # Create the button to load encrypted data
        self.button_load_encrypted_data = QPushButton("Load Encrypted Data")
        self.button_load_encrypted_data.clicked.connect(self.load_encrypted_data)

        # Create the button to copy encrypted data to clipboard
        self.button_copy_encrypted_data = QPushButton("Copy Encrypted Data")
        self.button_copy_encrypted_data.clicked.connect(self.copy_encrypted_data)

        # Create the button to paste encrypted data from clipboard
        self.button_paste_encrypted_data = QPushButton("Paste Encrypted Data")
        self.button_paste_encrypted_data.clicked.connect(self.paste_encrypted_data)

        # Set up the layout
        layout = QVBoxLayout()
        layout.addWidget(self.label_password)
        layout.addWidget(self.entry_password)
        layout.addWidget(self.button_check)
        layout.addWidget(self.label_strength)
        layout.addWidget(self.button_generate_strong_password)

        # Encrypt section layout
        encrypt_layout = QVBoxLayout()
        encrypt_layout.addWidget(self.label_data_to_encrypt)
        encrypt_layout.addWidget(self.entry_data_to_encrypt)
        encrypt_layout.addWidget(self.button_encrypt)
        encrypt_layout.addWidget(self.label_encrypted_data)
        encrypt_layout.addWidget(self.text_encrypted_data)

        # Decrypt section layout
        decrypt_layout = QVBoxLayout()
        decrypt_layout.addWidget(self.label_data_to_decrypt)
        decrypt_layout.addWidget(self.entry_data_to_decrypt)
        decrypt_layout.addWidget(self.button_decrypt)
        decrypt_layout.addWidget(self.label_decrypted_data)
        decrypt_layout.addWidget(self.text_decrypted_data)

        # Combine the encrypt and decrypt section layouts
        section_layout = QHBoxLayout()
        section_layout.addLayout(encrypt_layout)
        section_layout.addLayout(decrypt_layout)

        # Add the save and load buttons to the section layout
        section_layout.addWidget(self.button_save_encrypted_data)
        section_layout.addWidget(self.button_load_encrypted_data)
        section_layout.addWidget(self.button_copy_encrypted_data)
        section_layout.addWidget(self.button_paste_encrypted_data)

        layout.addLayout(section_layout)

        # Set the central widget and layout
        widget = QWidget()
        widget.setLayout(layout)
        self.setCentralWidget(widget)

    def check_password_strength(self):
        password = self.entry_password.text()

        # Create a password policy object
        policy = PasswordPolicy.from_names(
            length=8,  # minimum length of password
            uppercase=1,  # need at least 1 uppercase letter
            numbers=1,  # need at least 1 digit
            special=1,  # need at least 1 special character
        )

        # Check the password against the policy
        result = policy.test(password)

        # Set the label text and style based on password strength
        if result:
            strength_text = "Weak"
            strength_color = "red"
            self.prompt_generate_strong_password()
        else:
            strength_text = "Strong"
            strength_color = "green"

        self.label_strength.setText(strength_text)
        self.label_strength.setStyleSheet(f"color: {strength_color}; font-weight: bold;")

    def prompt_generate_strong_password(self):
        response = QMessageBox.question(
            self, "Weak Password",
            "The entered password is weak. Would you like to generate a strong password instead?",
            QMessageBox.Yes | QMessageBox.No
        )

        if response == QMessageBox.Yes:
            self.generate_strong_password()

    def generate_strong_password(self):
        length = 12  # Length of the generated password
        characters = string.ascii_letters + string.digits + string.punctuation
        strong_password = ''.join(secrets.choice(characters) for _ in range(length))
        self.entry_password.setText(strong_password)
        self.save_password()

    def save_password(self):
        password = self.entry_password.text()
        file_path = "passwords.txt"  # Path to the password file
        with open(file_path, "w") as file:
            file.write(password)

    def generate_key(self, password):
        salt = b"12345678"  # Replace this with a random salt for production use
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        fernet_key = base64.urlsafe_b64encode(key)  # Convert the key to URL-safe base64 format
        return fernet_key

    def encrypt_data(self):
        password = self.entry_password.text()
        data = self.entry_data_to_encrypt.text()  # Get the data to encrypt from the text field
        key = self.generate_key(password)
        encrypted_data = self.encrypt_with_fernet(key, data.encode())
        self.text_encrypted_data.setPlainText(base64.urlsafe_b64encode(encrypted_data).decode())

    def decrypt_data(self):
        password = self.entry_password.text()
        data = base64.urlsafe_b64decode(self.entry_data_to_decrypt.text())  # Get the data to decrypt and decode from base64
        key = self.generate_key(password)
        decrypted_data = self.decrypt_with_fernet(key, data)
        self.text_decrypted_data.setPlainText(decrypted_data.decode())

    def encrypt_with_fernet(self, key, data):
        # Generate a Fernet symmetric encryption key
        fernet_key = Fernet(key)

        # Encrypt the data
        encrypted_data = fernet_key.encrypt(data)

        return encrypted_data

    def decrypt_with_fernet(self, key, data):
        # Generate a Fernet symmetric encryption key
        fernet_key = Fernet(key)

        # Decrypt the data
        decrypted_data = fernet_key.decrypt(data)

        return decrypted_data

    def save_encrypted_data(self):
        encrypted_data = self.text_encrypted_data.toPlainText()
        if not encrypted_data:
            QMessageBox.warning(self, "No Data", "No encrypted data to save.")
            return

        file_path, _ = QFileDialog.getSaveFileName(self, "Save Encrypted Data", "", "Text Files (.txt);;All Files ()")
        if file_path:
            try:
                with open(file_path, "wb") as file:  # Use 'wb' mode to write binary data
                    file.write(base64.urlsafe_b64decode(encrypted_data))  # Decode the data before saving
                QMessageBox.information(self, "Save Success", "Encrypted data saved successfully.")
            except Exception as e:
                QMessageBox.critical(self, "Save Error", f"Failed to save encrypted data:\n{str(e)}")

    def load_encrypted_data(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Load Encrypted Data", "", "Text Files (.txt);;All Files ()")
        if file_path:
            try:
                with open(file_path, "rb") as file:  # Use 'rb' mode to read binary data
                    encrypted_data = file.read()
                self.text_encrypted_data.setPlainText(base64.urlsafe_b64encode(encrypted_data).decode())
            except Exception as e:
                QMessageBox.critical(self, "Load Error", f"Failed to load encrypted data:\n{str(e)}")

    def copy_encrypted_data(self):
        clipboard = QApplication.clipboard()
        encrypted_data_str = base64.urlsafe_b64encode(self.text_encrypted_data.toPlainText().encode()).decode()
        clipboard.setText(encrypted_data_str)

    def paste_encrypted_data(self):
        clipboard = QApplication.clipboard()
        encrypted_data_str = clipboard.text()

        try:
            encrypted_data = base64.urlsafe_b64decode(encrypted_data_str)
        except base64.binascii.Error:
            QMessageBox.critical(self, "Paste Error", "Invalid encrypted data format.")
            return

        self.entry_data_to_decrypt.setText(encrypted_data.decode())


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PasswordStrengthChecker()
    window.show()
    sys.exit(app.exec_())