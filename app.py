from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, send_file
import hashlib
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from database import DatabaseManager
from config import Config
import io

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = 'your-secret-key-here'

db = DatabaseManager()

class EncryptionModule:
    def __init__(self):
        self.key_size = 32
    
    def generate_content_key(self, data):
        return hashlib.sha256(data).digest()
    
    def mix_keys(self, content_key, random_component):
        h = hashlib.sha256()
        h.update(content_key)
        h.update(random_component)
        return h.digest()
    
    def encrypt_data(self, data, key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(data) + encryptor.finalize()
        return iv + encrypted
    
    def decrypt_data(self, encrypted_data, key):
        iv = encrypted_data[:16]
        actual_data = encrypted_data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(actual_data) + decryptor.finalize()
    
    def mixed_message_locked_encryption(self, data):
        content_key = self.generate_content_key(data)
        random_component = os.urandom(16)
        mixed_key = self.mix_keys(content_key, random_component)
        encrypted_data = self.encrypt_data(data, mixed_key)
        stub = hashlib.sha256(mixed_key).digest()
        return encrypted_data, mixed_key, stub, random_component

class DeduplicationModule:
    def __init__(self, db):
        self.db = db
        self.encryption = EncryptionModule()
        self.chunk_size = Config.CHUNK_SIZE
    
    def calculate_hash(self, data):
        return hashlib.sha256(data).hexdigest()
    
    def chunk_file(self, file_data):
        chunks = []
        for i in range(0, len(file_data), self.chunk_size):
            chunks.append(file_data[i:i + self.chunk_size])
        return chunks
    
    def process_file_upload(self, file_data, file_name, user_id):
        print(f"📁 Processing file upload: {file_name}, size: {len(file_data)} bytes, user: {user_id}")
        
        # Calculate file hash
        file_hash = self.calculate_hash(file_data)
        print(f"🔍 File hash: {file_hash}")
        
        # Check if file already exists
        existing_file = db.get_file_by_hash(file_hash)
        if existing_file:
            print("🔄 File already exists (deduplication working!)")
            return {"status": "duplicate", "file_id": existing_file[0]}
        
        # Split file into chunks
        chunks = self.chunk_file(file_data)
        print(f"📦 Split into {len(chunks)} chunks")
        
        chunk_hashes = []
        
        # Process each chunk
        for i, chunk in enumerate(chunks):
            chunk_hash = self.calculate_hash(chunk)
            print(f"  Chunk {i+1}: {chunk_hash}")
            
            if not db.chunk_exists(chunk_hash):
                print(f"    🔒 Encrypting and storing new chunk")
                encrypted_chunk, mixed_key, stub, random_comp = self.encryption.mixed_message_locked_encryption(chunk)
                db.store_chunk(chunk_hash, encrypted_chunk)
            else:
                print(f"    ✅ Chunk already exists (deduplication)")
            
            chunk_hashes.append(chunk_hash)
        
        # Encrypt entire file for metadata (simplified for demo)
        encrypted_file, file_key, file_stub, file_random = self.encryption.mixed_message_locked_encryption(file_data[:1000])  # Store only first 1000 bytes for demo
        
        # Store file metadata
        file_id = db.store_file_metadata(
            file_hash, 
            file_name, 
            len(file_data), 
            user_id,
            base64.b64encode(file_key).decode('utf-8'),
            base64.b64encode(file_stub).decode('utf-8'),
            base64.b64encode(file_random).decode('utf-8')
        )
        
        if file_id:
            # Store chunk mapping
            db.store_chunk_mapping(file_id, chunk_hashes)
            print(f"✅ File upload completed successfully. File ID: {file_id}")
            return {"status": "uploaded", "file_id": file_id}
        else:
            print("❌ Failed to store file metadata")
            return {"status": "error", "message": "Failed to store file"}
    
    def reconstruct_file(self, file_id, user_id):
        """Reconstruct file from chunks for download"""
        if not db.can_access_file(user_id, file_id):
            return None
        
        # Get file metadata
        file_data = db.get_file_by_id(file_id)
        if not file_data:
            return None
        
        # Get chunk hashes for this file
        chunk_hashes = db.get_file_chunks(file_id)
        if not chunk_hashes:
            return None
        
        # Reconstruct file from chunks (simplified - in real implementation, decrypt chunks)
        reconstructed_data = b""
        for chunk_hash in chunk_hashes:
            # Get chunk data (in real implementation, decrypt it)
            chunk_data = db.get_chunk_data(chunk_hash)
            if chunk_data:
                # For demo, just append the data (in real implementation, decrypt first)
                reconstructed_data += chunk_data
        
        return reconstructed_data[:file_data[3]]  # Return only up to original file size

encryption = EncryptionModule()
dedup = DeduplicationModule(db)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = db.get_user(username)
        
        if user:
            # Verify password
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            if user[3] == password_hash:
                session['user_id'] = user[0]
                session['username'] = user[1]
                print(f"✅ User {username} logged in successfully")
                return redirect(url_for('dashboard'))
        
        print(f"❌ Login failed for user: {username}")
        flash('Invalid credentials')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if db.user_exists(username):
            flash('Username already exists')
        else:
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            if db.create_user(username, email, password_hash):
                flash('Registration successful! Please login.')
                print(f"✅ New user registered: {username}")
                return redirect(url_for('login'))
            else:
                flash('Registration failed. Please try again.')
    
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get user's owned files AND shared files
    owned_files = db.get_user_owned_files(session['user_id'])
    shared_files = db.get_shared_files(session['user_id'])
    shared_access = db.get_shared_by_user(session['user_id'])
    
    print(f"📊 Dashboard: {len(owned_files)} owned files, {len(shared_files)} shared files, {len(shared_access)} shared by user for user {session['username']}")
    
    return render_template('dashboard.html', 
                         username=session['username'], 
                         owned_files=owned_files,
                         shared_files=shared_files,
                         shared_access=shared_access)

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)
        
        try:
            file_data = file.read()
            print(f"📤 Uploading file: {file.filename}, size: {len(file_data)} bytes")
            
            result = dedup.process_file_upload(file_data, file.filename, session['user_id'])
            
            if result['status'] == 'duplicate':
                flash('File already exists (deduplication working!)')
            elif result['status'] == 'uploaded':
                flash('File uploaded successfully with deduplication')
            else:
                flash('Upload failed')
                
        except Exception as e:
            print(f"❌ Upload error: {e}")
            flash('Error uploading file')
        
        return redirect(url_for('dashboard'))
    
    return render_template('upload.html')

@app.route('/download/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Check if user has access to this file
    if not db.can_access_file(session['user_id'], file_id):
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    # Get file metadata
    file_data = db.get_file_by_id(file_id)
    if not file_data:
        flash('File not found')
        return redirect(url_for('dashboard'))
    
    # For demo purposes, create a simple file
    # In real implementation, use dedup.reconstruct_file(file_id, session['user_id'])
    file_name = file_data[2]
    file_content = f"This is a demo download of {file_name}. In real implementation, file would be reconstructed from encrypted chunks.".encode()
    
    return send_file(
        io.BytesIO(file_content),
        as_attachment=True,
        download_name=file_name,
        mimetype='application/octet-stream'
    )

@app.route('/edit/<int:file_id>', methods=['GET', 'POST'])
def edit_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Check if user has write access to this file
    if not db.can_edit_file(session['user_id'], file_id):
        flash('You do not have permission to edit this file')
        return redirect(url_for('dashboard'))
    
    # Get file metadata
    file_data = db.get_file_by_id(file_id)
    if not file_data:
        flash('File not found')
        return redirect(url_for('dashboard'))
    
    file_name = file_data[2]
    file_owner = file_data[4]
    
    if request.method == 'POST':
        # Handle file edit/update
        if 'file' not in request.files:
            flash('No file selected')
            return redirect(request.url)
        
        new_file = request.files['file']
        if new_file.filename == '':
            flash('No file selected')
            return redirect(request.url)
        
        try:
            new_file_data = new_file.read()
            print(f"📝 Editing file: {file_name}, new size: {len(new_file_data)} bytes")
            
            # Process the new file with deduplication
            result = dedup.process_file_upload(new_file_data, file_name, session['user_id'])
            
            if result['status'] == 'uploaded':
                flash(f'File "{file_name}" updated successfully!')
                print(f"✅ File edited: {file_name} by user {session['username']}")
            else:
                flash('Failed to update file')
                
        except Exception as e:
            print(f"❌ Edit error: {e}")
            flash('Error updating file')
        
        return redirect(url_for('dashboard'))
    
    # GET request - show edit form
    return render_template('edit_file.html', 
                         file_id=file_id, 
                         file_name=file_name,
                         is_owner=(file_owner == session['user_id']))

@app.route('/files')
def list_files():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get user's owned files AND shared files
    owned_files = db.get_user_owned_files(session['user_id'])
    shared_files = db.get_shared_files(session['user_id'])
    
    print(f"📁 Files page: {len(owned_files)} owned files, {len(shared_files)} shared files for user {session['username']}")
    
    return render_template('files.html', 
                         owned_files=owned_files,
                         shared_files=shared_files)

@app.route('/share', methods=['GET', 'POST'])
def share_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        file_id = request.form['file_id']
        target_username = request.form['username']
        access_type = request.form['access_type']
        
        # Get target user
        target_user = db.get_user(target_username)
        if not target_user:
            flash('User not found')
            return redirect(url_for('share_file'))
        
        # Check if user owns the file
        file_owner = db.execute_query(
            "SELECT owner_id FROM files WHERE id = %s AND owner_id = %s",
            (file_id, session['user_id'])
        )
        
        if not file_owner:
            flash('File not found or access denied')
            return redirect(url_for('share_file'))
        
        # Check if access already exists
        existing_access = db.execute_query(
            "SELECT id FROM file_access WHERE file_id = %s AND user_id = %s AND is_revoked = FALSE",
            (file_id, target_user[0])
        )
        
        if existing_access:
            flash('Access already granted to this user')
            return redirect(url_for('share_file'))
        
        # Grant access
        if db.grant_file_access(file_id, target_user[0], access_type):
            flash(f'Access granted successfully to {target_username}')
            print(f"✅ Access granted: User {target_username} can {access_type} file {file_id}")
        else:
            flash('Failed to grant access')
        
        return redirect(url_for('dashboard'))
    
    # Get user's owned files for sharing
    owned_files = db.get_user_owned_files(session['user_id'])
    # Get shared access records for revoking
    shared_access = db.get_shared_by_user(session['user_id'])
    
    return render_template('share.html', files=owned_files, shared_access=shared_access)

@app.route('/revoke-access', methods=['POST'])
def revoke_access():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    access_id = request.form['access_id']
    
    # Verify the user owns the file being shared
    access_record = db.get_access_record(access_id)
    if not access_record:
        flash('Access record not found')
        return redirect(url_for('share_file'))
    
    file_id = access_record[1]
    
    # Check if user owns the file
    file_owner = db.execute_query(
        "SELECT owner_id FROM files WHERE id = %s AND owner_id = %s",
        (file_id, session['user_id'])
    )
    
    if not file_owner:
        flash('Access denied')
        return redirect(url_for('share_file'))
    
    # Revoke access
    if db.revoke_file_access_by_id(access_id):
        flash('Access revoked successfully')
        print(f"✅ Access revoked: Access ID {access_id}")
    else:
        flash('Failed to revoke access')
    
    return redirect(url_for('share_file'))

@app.route('/shared-with-me')
def shared_with_me():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    shared_files = db.get_shared_files(session['user_id'])
    print(f"📁 Shared files: {len(shared_files)} files shared with user {session['username']}")
    
    return render_template('shared_files.html', shared_files=shared_files)

@app.route('/logout')
def logout():
    print(f"👋 User {session.get('username', 'Unknown')} logged out")
    session.clear()
    return redirect(url_for('index'))

# Debug route to check database status
@app.route('/debug')
def debug():
    if 'user_id' not in session:
        return "Not logged in"
    
    owned_files = db.get_user_owned_files(session['user_id'])
    shared_files = db.get_shared_files(session['user_id'])
    all_files = db.execute_query("SELECT * FROM files")
    all_users = db.execute_query("SELECT * FROM users")
    all_access = db.execute_query("SELECT * FROM file_access")
    
    return f"""
    <h1>Debug Information</h1>
    <h2>User: {session['username']} (ID: {session['user_id']})</h2>
    
    <h3>Owned Files ({len(owned_files)})</h3>
    <pre>{owned_files}</pre>
    
    <h3>Shared Files ({len(shared_files)})</h3>
    <pre>{shared_files}</pre>
    
    <h3>All Files in Database ({len(all_files)})</h3>
    <pre>{all_files}</pre>
    
    <h3>All Users ({len(all_users)})</h3>
    <pre>{all_users}</pre>
    
    <h3>All Access Records ({len(all_access)})</h3>
    <pre>{all_access}</pre>
    
    <a href="/dashboard">Back to Dashboard</a>
    """

if __name__ == '__main__':
    # Create upload directories
    os.makedirs('uploads/chunks', exist_ok=True)
    os.makedirs('uploads/temp', exist_ok=True)
    
    print("🚀 Starting Secure Deduplication Server...")
    print("📊 Database initialized")
    print("🌐 Server running ")
    
    app.run(debug=True)