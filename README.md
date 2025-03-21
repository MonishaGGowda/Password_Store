# 🔐 Password Vault (CLI)
A simple **password manager** written in Go that securely stores and retrieves passwords using AES encryption with a **master password**.

## 🚀 Features
- 🔒 **AES-256 Encryption** for password security.
- 🔑 **Master Password Protection**.
- 🖥️ **Command-line Interface (CLI)**.
- 💾 **Local file-based storage (`vault.db`)**.

---

## 📦 Installation

1.**Clone the repository**:
git clone https://github.com/MonishaGGowda/password-vault.git
cd password-vault

2.**Build the binary:**
 go build -o vault

3. **Store a password**
./vault add <service> <password>

4. **Retrieve a password**
./vault get <service>

## 🔑Security Considerations
- DO NOT share your master password
- Set strict file permissions for vault.db:
  chmod 600 vault.db
