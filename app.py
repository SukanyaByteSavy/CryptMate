import os
import logging
from flask import Flask, render_template, request, send_file, jsonify
from werkzeug.utils import secure_filename
from crypto_utils import generate_key_pair, encrypt_file_rsa, decrypt_file_rsa, encrypt_file_aes, decrypt_file_aes
import tempfile
from cryptography.hazmat.primitives import serialization

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default-secret-key")

# Configuration
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        if 'file' not in request.files:
            logger.error("No file uploaded")
            return jsonify({'error': 'No file uploaded'}), 400

        file = request.files['file']
        if file.filename == '':
            logger.error("No file selected")
            return jsonify({'error': 'No file selected'}), 400

        if not allowed_file(file.filename):
            logger.error(f"File type not allowed: {file.filename}")
            return jsonify({'error': 'File type not allowed'}), 400

        encryption_type = request.form.get('encryption_type', 'aes')
        logger.debug(f"Starting {encryption_type} encryption for file: {file.filename}")

        # Create temporary file
        with tempfile.NamedTemporaryFile(delete=False) as temp_in:
            file.save(temp_in.name)
            logger.debug(f"Saved uploaded file to: {temp_in.name}")

            try:
                if encryption_type == 'rsa':
                    public_key, private_key = generate_key_pair()
                    encrypted_file = encrypt_file_rsa(temp_in.name, public_key)
                    # Convert private key to PEM format for decryption
                    private_key_pem = private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ).decode('utf-8')
                    logger.debug("RSA encryption completed successfully")
                    return jsonify({
                        'file_url': f'/download/{os.path.basename(encrypted_file)}',
                        'key': private_key_pem,
                        'filename': secure_filename(file.filename) + '.encrypted'
                    })
                else:  # AES
                    key, encrypted_file = encrypt_file_aes(temp_in.name)
                    logger.debug("AES encryption completed successfully")
                    return jsonify({
                        'file_url': f'/download/{os.path.basename(encrypted_file)}',
                        'key': key,
                        'filename': secure_filename(file.filename) + '.encrypted'
                    })
            finally:
                # Clean up the temporary input file
                os.unlink(temp_in.name)

    except Exception as e:
        logger.error(f"Encryption error: {str(e)}")
        return jsonify({'error': f'Encryption failed: {str(e)}'}), 500

@app.route('/download/<filename>')
def download_file(filename):
    try:
        logger.debug(f"Downloading file: {filename}")
        return send_file(
            os.path.join(tempfile.gettempdir(), filename),
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        logger.error(f"Download error: {str(e)}")
        return jsonify({'error': 'File download failed'}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        if 'file' not in request.files:
            logger.error("No file uploaded for decryption")
            return jsonify({'error': 'No file uploaded'}), 400

        file = request.files['file']
        if file.filename == '':
            logger.error("No file selected for decryption")
            return jsonify({'error': 'No file selected'}), 400

        encryption_type = request.form.get('encryption_type', 'aes')
        key = request.form.get('key', '')
        logger.debug(f"Starting {encryption_type} decryption for file: {file.filename}")

        # Create temporary file
        with tempfile.NamedTemporaryFile(delete=False) as temp_in:
            file.save(temp_in.name)
            logger.debug(f"Saved encrypted file to: {temp_in.name}")

            try:
                if encryption_type == 'rsa':
                    decrypted_file = decrypt_file_rsa(temp_in.name, key)
                else:  # AES
                    decrypted_file = decrypt_file_aes(temp_in.name, key)
                logger.debug("Decryption completed successfully")

                return send_file(
                    decrypted_file,
                    as_attachment=True,
                    download_name=secure_filename(file.filename.replace('.encrypted', ''))
                )
            finally:
                # Clean up the temporary input file
                os.unlink(temp_in.name)

    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)