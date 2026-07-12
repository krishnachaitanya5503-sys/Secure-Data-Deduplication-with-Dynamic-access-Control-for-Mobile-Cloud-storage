import mysql.connector
from config import Config
import hashlib
import base64

class DatabaseManager:
    def __init__(self):
        self.config = Config()
        self.connection = None
        self.connect()
        self.create_tables()
    
    def connect(self):
        try:
            self.connection = mysql.connector.connect(
                host=self.config.MYSQL_HOST,
                user=self.config.MYSQL_USER,
                password=self.config.MYSQL_PASSWORD,
                database=self.config.MYSQL_DB
            )
            print("✅ Connected to MySQL database")
        except mysql.connector.Error as err:
            print(f"❌ Connection error: {err}")
            self.create_database()
    
    def create_database(self):
        try:
            conn = mysql.connector.connect(
                host=self.config.MYSQL_HOST,
                user=self.config.MYSQL_USER,
                password=self.config.MYSQL_PASSWORD
            )
            cursor = conn.cursor()
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {self.config.MYSQL_DB}")
            print(f"✅ Database {self.config.MYSQL_DB} created")
            conn.commit()
            cursor.close()
            conn.close()
            self.connect()
        except mysql.connector.Error as err:
            print(f"❌ Database creation error: {err}")
    
    def create_tables(self):
        cursor = self.connection.cursor()
        
        try:
            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            print("✅ Users table created/verified")
            
            # Files table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    file_hash VARCHAR(255) UNIQUE NOT NULL,
                    file_name VARCHAR(255) NOT NULL,
                    file_size BIGINT NOT NULL,
                    owner_id INT NOT NULL,
                    encrypted_key TEXT NOT NULL,
                    stub_key TEXT NOT NULL,
                    random_component TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
                )
            ''')
            print("✅ Files table created/verified")
            
            # File chunks table for deduplication
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_chunks (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    chunk_hash VARCHAR(255) UNIQUE NOT NULL,
                    encrypted_data LONGBLOB NOT NULL,
                    reference_count INT DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            print("✅ File chunks table created/verified")
            
            # File chunk mapping
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_chunk_mapping (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    file_id INT NOT NULL,
                    chunk_hash VARCHAR(255) NOT NULL,
                    chunk_order INT NOT NULL,
                    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
                )
            ''')
            print("✅ File chunk mapping table created/verified")
            
            # Access control table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_access (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    file_id INT NOT NULL,
                    user_id INT NOT NULL,
                    access_type ENUM('read', 'write') DEFAULT 'read',
                    is_revoked BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    UNIQUE KEY unique_file_user (file_id, user_id)
                )
            ''')
            print("✅ File access table created/verified")
            
            self.connection.commit()
            print("✅ All tables created successfully")
            
        except mysql.connector.Error as err:
            print(f"❌ Table creation error: {err}")
        finally:
            cursor.close()
    
    def execute_query(self, query, params=None):
        try:
            cursor = self.connection.cursor()
            cursor.execute(query, params or ())
            result = cursor.fetchall()
            cursor.close()
            return result
        except mysql.connector.Error as err:
            print(f"❌ Query error: {err}")
            return []
    
    def execute_update(self, query, params=None):
        try:
            cursor = self.connection.cursor()
            cursor.execute(query, params or ())
            self.connection.commit()
            cursor.close()
            return True
        except mysql.connector.Error as err:
            print(f"❌ Update error: {err}")
            return False
    
    def user_exists(self, username):
        result = self.execute_query("SELECT id FROM users WHERE username = %s", (username,))
        return len(result) > 0
    
    def create_user(self, username, email, password_hash):
        return self.execute_update(
            "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
            (username, email, password_hash)
        )
    
    def get_user(self, username):
        result = self.execute_query(
            "SELECT id, username, email, password_hash FROM users WHERE username = %s", 
            (username,)
        )
        return result[0] if result else None
    
    def chunk_exists(self, chunk_hash):
        result = self.execute_query("SELECT id FROM file_chunks WHERE chunk_hash = %s", (chunk_hash,))
        return len(result) > 0
    
    def store_chunk(self, chunk_hash, encrypted_data):
        if not self.chunk_exists(chunk_hash):
            return self.execute_update(
                "INSERT INTO file_chunks (chunk_hash, encrypted_data) VALUES (%s, %s)",
                (chunk_hash, encrypted_data)
            )
        else:
            return self.execute_update(
                "UPDATE file_chunks SET reference_count = reference_count + 1 WHERE chunk_hash = %s",
                (chunk_hash,)
            )
    
    def store_file_metadata(self, file_hash, file_name, file_size, owner_id, encrypted_key, stub_key, random_component):
        try:
            # First check if file already exists
            existing = self.get_file_by_hash(file_hash)
            if existing:
                print(f"⚠️ File already exists with hash: {file_hash}")
                return existing[0]  # Return existing file ID
            
            # Insert new file
            cursor = self.connection.cursor()
            cursor.execute(
                """INSERT INTO files (file_hash, file_name, file_size, owner_id, encrypted_key, stub_key, random_component) 
                   VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (file_hash, file_name, file_size, owner_id, encrypted_key, stub_key, random_component)
            )
            file_id = cursor.lastrowid
            self.connection.commit()
            cursor.close()
            print(f"✅ File metadata stored with ID: {file_id}")
            return file_id
        except mysql.connector.Error as err:
            print(f"❌ Error storing file metadata: {err}")
            return None
    
    def get_file_by_hash(self, file_hash):
        result = self.execute_query("SELECT * FROM files WHERE file_hash = %s", (file_hash,))
        return result[0] if result else None
    
    def get_file_by_id(self, file_id):
        result = self.execute_query("SELECT * FROM files WHERE id = %s", (file_id,))
        return result[0] if result else None
    
    def get_user_owned_files(self, user_id):
        """Get files owned by the user"""
        return self.execute_query(
            "SELECT id, file_name, file_size, created_at FROM files WHERE owner_id = %s ORDER BY created_at DESC",
            (user_id,)
        )
    
    def get_shared_files(self, user_id):
        """Get files shared with the user"""
        query = """
        SELECT f.id, f.file_name, f.file_size, f.created_at, 
               fa.access_type, u.username as owner_name
        FROM files f
        JOIN file_access fa ON f.id = fa.file_id 
        JOIN users u ON f.owner_id = u.id
        WHERE fa.user_id = %s AND fa.is_revoked = FALSE
        ORDER BY f.created_at DESC
        """
        return self.execute_query(query, (user_id,))
    
    def get_shared_by_user(self, user_id):
        """Get files that the user has shared with others"""
        query = """
        SELECT fa.id, fa.file_id, f.file_name, u.username as shared_with, 
               fa.access_type, fa.created_at
        FROM file_access fa
        JOIN files f ON fa.file_id = f.id
        JOIN users u ON fa.user_id = u.id
        WHERE f.owner_id = %s AND fa.is_revoked = FALSE
        ORDER BY fa.created_at DESC
        """
        return self.execute_query(query, (user_id,))
    
    def get_access_record(self, access_id):
        """Get specific access record"""
        result = self.execute_query("SELECT * FROM file_access WHERE id = %s", (access_id,))
        return result[0] if result else None
    
    def get_file_chunks(self, file_id):
        """Get chunk hashes for a file"""
        result = self.execute_query(
            "SELECT chunk_hash FROM file_chunk_mapping WHERE file_id = %s ORDER BY chunk_order",
            (file_id,)
        )
        return [row[0] for row in result] if result else []
    
    def get_chunk_data(self, chunk_hash):
        """Get chunk data by hash"""
        result = self.execute_query(
            "SELECT encrypted_data FROM file_chunks WHERE chunk_hash = %s",
            (chunk_hash,)
        )
        return result[0][0] if result else None
    
    def store_chunk_mapping(self, file_id, chunk_hashes):
        """Store the mapping between file and its chunks"""
        try:
            for order, chunk_hash in enumerate(chunk_hashes):
                self.execute_update(
                    "INSERT INTO file_chunk_mapping (file_id, chunk_hash, chunk_order) VALUES (%s, %s, %s)",
                    (file_id, chunk_hash, order)
                )
            print(f"✅ Stored {len(chunk_hashes)} chunk mappings for file {file_id}")
            return True
        except mysql.connector.Error as err:
            print(f"❌ Error storing chunk mappings: {err}")
            return False
    
    def grant_file_access(self, file_id, target_user_id, access_type='read'):
        """Grant access to a file for another user"""
        return self.execute_update(
            "INSERT INTO file_access (file_id, user_id, access_type) VALUES (%s, %s, %s)",
            (file_id, target_user_id, access_type)
        )
    
    def revoke_file_access(self, file_id, target_user_id):
        """Revoke access to a file for a user"""
        return self.execute_update(
            "UPDATE file_access SET is_revoked = TRUE WHERE file_id = %s AND user_id = %s",
            (file_id, target_user_id)
        )
    
    def revoke_file_access_by_id(self, access_id):
        """Revoke access by access record ID"""
        return self.execute_update(
            "UPDATE file_access SET is_revoked = TRUE WHERE id = %s",
            (access_id,)
        )
    
    def can_access_file(self, user_id, file_id, required_access='read'):
        """Check if user has access to file"""
        query = """
        SELECT 1 FROM files f 
        LEFT JOIN file_access fa ON f.id = fa.file_id AND fa.user_id = %s AND fa.is_revoked = FALSE
        WHERE f.id = %s AND (f.owner_id = %s OR (fa.user_id = %s AND fa.access_type IN ('read', 'write')))
        """
        result = self.execute_query(query, (user_id, file_id, user_id, user_id))
        return len(result) > 0
    
    def can_edit_file(self, user_id, file_id):
        """Check if user has edit permission for file"""
        query = """
        SELECT 1 FROM files f 
        LEFT JOIN file_access fa ON f.id = fa.file_id AND fa.user_id = %s AND fa.is_revoked = FALSE
        WHERE f.id = %s AND (f.owner_id = %s OR (fa.user_id = %s AND fa.access_type = 'write'))
        """
        result = self.execute_query(query, (user_id, file_id, user_id, user_id))
        return len(result) > 0