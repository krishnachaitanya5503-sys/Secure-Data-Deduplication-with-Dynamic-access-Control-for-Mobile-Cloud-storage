# Secure-Data-Deduplication-with-Dynamic-access-Control-for-Mobile-Cloud-storage
A secure cloud storage system that eliminates duplicate data using secure deduplication while providing dynamic attribute-based access control, encrypted storage, and user revocation for mobile cloud environments.
Overview

Secure Data Deduplication with Dynamic Access Control for Mobile Cloud Storage is a cloud security project designed to optimize storage utilization while preserving data confidentiality and privacy. The system securely identifies duplicate files, stores only a single encrypted copy, and enables fine-grained access control for authorized users.

The project combines secure deduplication with modern cryptographic techniques to reduce storage overhead without compromising data security. It also supports dynamic user revocation, ensuring that revoked users cannot access previously shared data.

Features
Secure user registration and authentication
Secure file upload and download
SHA-256 based duplicate file detection
Secure encrypted cloud storage
Mixed Message-Locked Encryption (MMLE)
Attribute-Based Encryption (ABE) for access control
Dynamic user access management
User revocation and secure re-encryption
Cloud storage optimization through deduplication
Protection against unauthorized access
Mobile cloud storage support
Technologies Used
Python
Flask
HTML
CSS
JavaScript
MySQL / SQLite
SHA-256
AES Encryption
Attribute-Based Encryption (ABE)
Mixed Message-Locked Encryption (MMLE)
Project Architecture

The project consists of the following modules:

User Management Module
File Upload Module
Hash Generation Module
Deduplication Module
Encryption Module
Access Control Module
User Revocation Module
Cloud Storage Module
Database Management Module
How It Works
User registers and logs into the system.
User uploads a file.
SHA-256 generates a unique hash for the file.
The system checks whether the file already exists.
If duplicate:
Only a reference is stored.
If new:
File is encrypted using MMLE.
Encrypted file is stored in cloud storage.
Attribute-Based Encryption controls access permissions.
Authorized users can securely access files.
Revoked users immediately lose access through secure key updates.
Advantages
Reduces cloud storage costs
Eliminates duplicate files
Strong data confidentiality
Secure encrypted storage
Fine-grained access control
Dynamic user revocation
Better cloud storage efficiency
Scalable for mobile cloud environments
Project Objectives
Reduce redundant cloud storage.
Improve cloud security.
Protect user privacy.
Enable secure data sharing.
Implement dynamic access control.
Optimize storage utilization.
Future Enhancements
Multi-cloud storage integration
Blockchain-based audit logs
AI-powered anomaly detection
Real-time intrusion detection
Advanced key management
Support for IoT cloud devices
