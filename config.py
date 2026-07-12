import os

class Config:
    MYSQL_HOST = 'localhost'
    MYSQL_USER = 'root'
    MYSQL_PASSWORD = 'root'
    MYSQL_DB = 'secure_dedup'
    SECRET_KEY = 'secure_dedup_secret_key_2024'
    UPLOAD_FOLDER = 'uploads/'
    CHUNK_SIZE = 1024 * 1024
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024