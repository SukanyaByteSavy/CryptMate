# 🔐 CryptMate

Welcome to **CryptMate** – a cryptographic utility built with Python and C++ for secure encryption and decryption tasks. This project combines the performance of C++ with the flexibility of Python to provide a robust and efficient encryption framework.

## 📂 Project Structure
```
CryptMate/
│── src/                      # C++ source code
│   ├── crypto_core.cpp       # Core cryptographic functions
│   ├── crypto_impl.cpp       # Python-C++ integration module
│── app.py                    # Main application script
│── main.py                   # Entry point of the project
│── crypto_utils.py           # Utility functions for cryptographic operations
│── CMakeLists.txt            # CMake configuration for building C++ code
│── crypto_impl.so            # Compiled C++ extension for Python
│── pyproject.toml            # Python project configuration
│── requirements.txt          # Python dependencies
```

## 🚀 Features
✅ High-performance cryptographic operations using C++
✅ Python integration for seamless usability
✅ Secure encryption & decryption
✅ Modular design for easy extensibility

## 🛠️ Setup Instructions
### 1️⃣ Clone the Repository
```bash
git clone https://github.com/SukanyaByteSavy/CryptMate.git
cd CryptMate
```

### 2️⃣ Install Dependencies
Make sure you have Python installed, then run:
```bash
pip install -r requirements.txt
```

### 3️⃣ Build the C++ Extension
CryptMate uses C++ for performance-critical operations. To compile the C++ code:
```bash
mkdir build && cd build
cmake ..
make
```
This will generate `crypto_impl.so`, which is used in Python.

### 4️⃣ Run the Application
```bash
python main.py
```

## 📝 How C++ is Used
The C++ files in `src/` handle encryption operations and integrate with Python:
- `crypto_core.cpp`: Implements core encryption algorithms.
- `crypto_impl.cpp`: Connects C++ logic with Python via a compiled shared library (`.so` file).

These files ensure **CryptMate** runs efficiently by offloading complex computations to C++ while keeping a Python-friendly interface.

## 📜 License
This project is licensed under the MIT License.

## 📧 Contact
For any queries, feel free to reach out at sukanyapatnaik520@gmail.com. 🚀

