# Image Encryption System

A secure desktop application for encrypting and decrypting images using various cryptographic algorithms. Built with Python and CustomTkinter for a modern user interface.

![Application Screenshot](https://via.placeholder.com/800x600/2b2b2b/ffffff?text=Image+Encryption+System)

## Features

- 🔒 Multiple encryption algorithms:
  - AES-GCM (Advanced Encryption Standard)
  - RSA (Rivest-Shamir-Adleman)
  - DES (Data Encryption Standard)
  - ChaCha20 (Stream Cipher)
- 👤 User authentication system
- 🖼️ Image preview before and after encryption/decryption
- 🎨 Modern and intuitive user interface
- 🔑 Secure key management
- 🌓 Light/Dark theme support

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/khaledawsd/IES-by-Tkinter.git
   cd IES-by-Tkinter
   ```

2. Create and activate a virtual environment (recommended):
   ```bash
   # Windows
   python -m venv venv
   .\venv\Scripts\activate
   
   # macOS/Linux
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:
   ```bash
   python main.py
   ```

2. Log in with your credentials (or register a new account)
3. Select an image using the file dialog or drag and drop
4. Choose an encryption method
5. Click "Encrypt" or "Decrypt" as needed
6. Save the encrypted/decrypted image

## Project Structure

```
IES-by-Tkinter/
├── assets/               # Icons and images
├── encryption.py         # Encryption/decryption logic
├── login.py              # User authentication
├── main.py               # Main application window
├── registration.py       # User registration
├── Admin.py              # Admin interface
├── Database.py           # Database operations
├── requirements.txt      # Project dependencies
└── README.md             # This file
```

## Dependencies

- `customtkinter` - Modern UI components
- `Pillow` - Image processing
- `pycryptodome` - Cryptographic functions
- `tkinterdnd2` - Drag and drop functionality
- `cryptography` - Additional cryptographic operations

## Security Notes

- Passwords are hashed with a unique salt before storage
- Encryption keys are generated using secure random number generation
- Sensitive data is handled securely in memory
- Always keep your encryption keys safe and never share them

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with Python and CustomTkinter
- Icons from [Material Design Icons](https://material.io/resources/icons/)
- Cryptographic implementations using PyCryptodome
