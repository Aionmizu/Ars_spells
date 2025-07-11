#!/usr/bin/env python3
"""
Backup script for the Spell Combos database.
This script:
1. Compresses the database file
2. Encrypts it with GPG
3. Uploads it to a storage bucket (Wasabi S3)

Usage:
    python backup.py

Requirements:
    - gnupg (pip install python-gnupg)
    - boto3 (pip install boto3)
    - A GPG key for encryption
    - Wasabi S3 credentials
"""

import os
import sys
import time
import zipfile
import gnupg
import boto3
import logging
from datetime import datetime
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("backup.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuration
DB_PATH = os.environ.get('DB_PATH', 'combos.db')
if os.path.exists('/data'):
    DB_PATH = '/data/combos.db'

BACKUP_DIR = os.environ.get('BACKUP_DIR', 'backups')
GPG_RECIPIENT = os.environ.get('GPG_RECIPIENT', 'aion38320@gmail.com')
WASABI_BUCKET = os.environ.get('WASABI_BUCKET', 'spell-combos-backups')
WASABI_REGION = os.environ.get('WASABI_REGION', 'eu-north-1')
WASABI_ENDPOINT = f'https://s3.{WASABI_REGION}.wasabisys.com'

# Ensure backup directory exists
os.makedirs(BACKUP_DIR, exist_ok=True)

def create_zip_backup(db_path, backup_dir):
    """Create a zip file containing the database"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    zip_filename = f"{backup_dir}/combos_backup_{timestamp}.zip"
    
    try:
        with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(db_path, os.path.basename(db_path))
        logger.info(f"Created zip backup: {zip_filename}")
        return zip_filename
    except Exception as e:
        logger.error(f"Failed to create zip backup: {e}")
        return None

def encrypt_file(file_path):
    """Encrypt a file using GPG"""
    try:
        gpg = gnupg.GPG()
        with open(file_path, 'rb') as f:
            encrypted_data = gpg.encrypt_file(
                f, 
                recipients=[GPG_RECIPIENT],
                output=f"{file_path}.gpg"
            )
        
        if encrypted_data.ok:
            logger.info(f"Encrypted file: {file_path}.gpg")
            return f"{file_path}.gpg"
        else:
            logger.error(f"Encryption failed: {encrypted_data.status}")
            return None
    except Exception as e:
        logger.error(f"Failed to encrypt file: {e}")
        return None

def upload_to_wasabi(file_path, bucket, object_name=None):
    """Upload a file to Wasabi S3"""
    if object_name is None:
        object_name = os.path.basename(file_path)
    
    # Create a session with Wasabi credentials
    session = boto3.session.Session()
    s3_client = session.client(
        's3',
        region_name=WASABI_REGION,
        endpoint_url=WASABI_ENDPOINT,
        aws_access_key_id=os.environ.get('WASABI_ACCESS_KEY'),
        aws_secret_access_key=os.environ.get('WASABI_SECRET_KEY')
    )
    
    try:
        s3_client.upload_file(file_path, bucket, object_name)
        logger.info(f"Uploaded {file_path} to {bucket}/{object_name}")
        return True
    except ClientError as e:
        logger.error(f"Failed to upload to Wasabi: {e}")
        return False

def cleanup_old_backups(backup_dir, keep_days=7):
    """Delete backups older than keep_days"""
    now = time.time()
    for filename in os.listdir(backup_dir):
        file_path = os.path.join(backup_dir, filename)
        if os.path.isfile(file_path):
            if os.stat(file_path).st_mtime < now - keep_days * 86400:
                try:
                    os.remove(file_path)
                    logger.info(f"Deleted old backup: {file_path}")
                except Exception as e:
                    logger.error(f"Failed to delete old backup {file_path}: {e}")

def main():
    """Main backup function"""
    logger.info("Starting database backup process")
    
    # Check if database exists
    if not os.path.exists(DB_PATH):
        logger.error(f"Database file not found: {DB_PATH}")
        return False
    
    # Create zip backup
    zip_file = create_zip_backup(DB_PATH, BACKUP_DIR)
    if not zip_file:
        return False
    
    # Encrypt the zip file
    encrypted_file = encrypt_file(zip_file)
    if not encrypted_file:
        return False
    
    # Upload to Wasabi
    if os.environ.get('WASABI_ACCESS_KEY') and os.environ.get('WASABI_SECRET_KEY'):
        upload_success = upload_to_wasabi(encrypted_file, WASABI_BUCKET)
        if not upload_success:
            logger.warning("Failed to upload to Wasabi, but backup files were created locally")
    else:
        logger.warning("Wasabi credentials not set, skipping upload")
    
    # Cleanup old backups
    cleanup_old_backups(BACKUP_DIR)
    
    logger.info("Backup process completed")
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)