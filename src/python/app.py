#!/usr/bin/env python3
"""
DistributedFS REST API Server
A Flask-based REST API for managing the distributed file storage system.
"""

import os
import json
import hashlib
import subprocess
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

from flask import Flask, request, jsonify, send_file, Response
from flask_cors import CORS
import sqlite3
import logging
from werkzeug.utils import secure_filename
from werkzeug.exceptions import BadRequest, NotFound, InternalServerError
import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Configuration
app.config.update({
    'MAX_CONTENT_LENGTH': 1024 * 1024 * 1024,  # 1GB max file size
    'UPLOAD_FOLDER': '/tmp/distributedfs_uploads',
    'STORAGE_PATH': '/tmp/distributedfs_storage',
    'DATABASE_PATH': '/tmp/distributedfs.db',
    'SECRET_KEY': 'your-secret-key-here',
    'API_VERSION': '1.0.0'
})

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['STORAGE_PATH'], exist_ok=True)


class DatabaseManager:
    """Manages SQLite database operations for metadata and configuration."""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database tables."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Files table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                file_id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                size INTEGER NOT NULL,
                checksum TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                access_count INTEGER DEFAULT 0,
                encrypted BOOLEAN DEFAULT 0
            )
        ''')
        
        # Users table for access control
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Access logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS access_logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id TEXT,
                user_id TEXT,
                action TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                FOREIGN KEY (file_id) REFERENCES files (file_id),
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        ''')
        
        # Configuration table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS configuration (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def execute_query(self, query: str, params: tuple = ()) -> List[Dict]:
        """Execute a query and return results."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        try:
            cursor.execute(query, params)
            if query.strip().upper().startswith('SELECT'):
                results = [dict(row) for row in cursor.fetchall()]
                conn.close()
                return results
            else:
                conn.commit()
                conn.close()
                return []
        except Exception as e:
            conn.close()
            logger.error(f"Database query error: {e}")
            raise


class SecurityManager:
    """Handles security, encryption, and vulnerability scanning."""
    
    def __init__(self):
        self.known_vulnerabilities = self.load_cve_database()
    
    def load_cve_database(self) -> Dict[str, List[str]]:
        """Load known CVE vulnerabilities database."""
        # In production, this would load from a real CVE database
        return {
            'openssl': ['CVE-2022-0778', 'CVE-2021-3449'],
            'python': ['CVE-2022-0391', 'CVE-2021-29921'],
            'flask': ['CVE-2018-1000656'],
            'boost': ['CVE-2012-2677']
        }
    
    def scan_for_vulnerabilities(self) -> Dict[str, Any]:
        """Perform security vulnerability scan."""
        vulnerabilities = []
        recommendations = []
        
        # Check installed packages
        try:
            result = subprocess.run(['pip', 'list'], capture_output=True, text=True)
            installed_packages = result.stdout.lower()
            
            for component, cves in self.known_vulnerabilities.items():
                if component in installed_packages:
                    vulnerabilities.extend(cves)
                    recommendations.append(f"Update {component} to latest version")
        except Exception as e:
            logger.error(f"Vulnerability scan error: {e}")
        
        return {
            'has_vulnerabilities': len(vulnerabilities) > 0,
            'cve_ids': vulnerabilities,
            'recommendations': recommendations,
            'scan_time': datetime.now().isoformat(),
            'scanned_components': list(self.known_vulnerabilities.keys())
        }
    
    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file."""
        hash_sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def validate_file_access(self, file_id: str, user_id: str) -> bool:
        """Validate if user has access to file."""
        # Simplified access control - in production, implement proper RBAC
        return True


# Initialize components
db_manager = DatabaseManager(app.config['DATABASE_PATH'])
security_manager = SecurityManager()


class StorageEngineInterface:
    """Interface to communicate with C++ storage engine."""
    
    def __init__(self, storage_path: str):
        self.storage_path = storage_path
        self.cpp_executable = None  # Path to C++ executable
    
    def store_file(self, filename: str, file_data: bytes) -> str:
        """Store file using C++ engine."""
        # For demonstration, we'll use Python implementation
        file_id = hashlib.sha256(f"{filename}{time.time()}".encode()).hexdigest()
        file_path = os.path.join(self.storage_path, file_id)
        
        with open(file_path, 'wb') as f:
            f.write(file_data)
        
        # Store metadata in database
        checksum = hashlib.sha256(file_data).hexdigest()
        db_manager.execute_query(
            "INSERT INTO files (file_id, filename, size, checksum) VALUES (?, ?, ?, ?)",
            (file_id, filename, len(file_data), checksum)
        )
        
        return file_id
    
    def retrieve_file(self, file_id: str) -> Optional[bytes]:
        """Retrieve file using C++ engine."""
        file_path = os.path.join(self.storage_path, file_id)
        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                return f.read()
        return None
    
    def delete_file(self, file_id: str) -> bool:
        """Delete file using C++ engine."""
        file_path = os.path.join(self.storage_path, file_id)
        if os.path.exists(file_path):
            os.remove(file_path)
            db_manager.execute_query("DELETE FROM files WHERE file_id = ?", (file_id,))
            return True
        return False
    
    def get_health_stats(self) -> Dict[str, Any]:
        """Get storage engine health statistics."""
        files = db_manager.execute_query("SELECT COUNT(*) as count, SUM(size) as total_size FROM files")
        storage_used = files[0]['total_size'] if files[0]['total_size'] else 0
        
        return {
            'total_files': files[0]['count'],
            'total_storage_bytes': storage_used,
            'storage_path': self.storage_path,
            'healthy': True,
            'uptime_seconds': time.time() - start_time
        }


storage_engine = StorageEngineInterface(app.config['STORAGE_PATH'])
start_time = time.time()


# API Routes
@app.route('/api/health', methods=['GET'])
def health_check():
    """System health check endpoint."""
    stats = storage_engine.get_health_stats()
    return jsonify({
        'status': 'healthy' if stats['healthy'] else 'unhealthy',
        'version': app.config['API_VERSION'],
        'timestamp': datetime.now().isoformat(),
        'storage_stats': stats,
        'memory_usage': get_memory_usage()
    })


@app.route('/api/files', methods=['POST'])
def upload_file():
    """Upload a new file."""
    if 'file' not in request.files:
        raise BadRequest('No file provided')
    
    file = request.files['file']
    if file.filename == '':
        raise BadRequest('No file selected')
    
    if file:
        filename = secure_filename(file.filename)
        file_data = file.read()
        
        # Validate file size
        if len(file_data) > app.config['MAX_CONTENT_LENGTH']:
            raise BadRequest('File too large')
        
        try:
            file_id = storage_engine.store_file(filename, file_data)
            
            # Log access
            db_manager.execute_query(
                "INSERT INTO access_logs (file_id, action, ip_address) VALUES (?, ?, ?)",
                (file_id, 'upload', request.remote_addr)
            )
            
            return jsonify({
                'file_id': file_id,
                'filename': filename,
                'size': len(file_data),
                'checksum': security_manager.calculate_file_hash(
                    os.path.join(app.config['STORAGE_PATH'], file_id)
                ),
                'uploaded_at': datetime.now().isoformat()
            }), 201
            
        except Exception as e:
            logger.error(f"File upload error: {e}")
            raise InternalServerError('Failed to store file')


@app.route('/api/files/<file_id>', methods=['GET'])
def download_file(file_id: str):
    """Download a file by ID."""
    # Get file metadata
    files = db_manager.execute_query(
        "SELECT * FROM files WHERE file_id = ?", (file_id,)
    )
    
    if not files:
        raise NotFound('File not found')
    
    file_info = files[0]
    
    # Retrieve file data
    file_data = storage_engine.retrieve_file(file_id)
    if not file_data:
        raise NotFound('File data not found')
    
    # Update access count
    db_manager.execute_query(
        "UPDATE files SET access_count = access_count + 1 WHERE file_id = ?",
        (file_id,)
    )
    
    # Log access
    db_manager.execute_query(
        "INSERT INTO access_logs (file_id, action, ip_address) VALUES (?, ?, ?)",
        (file_id, 'download', request.remote_addr)
    )
    
    return Response(
        file_data,
        mimetype='application/octet-stream',
        headers={
            'Content-Disposition': f'attachment; filename="{file_info["filename"]}"',
            'Content-Length': str(len(file_data))
        }
    )


@app.route('/api/files/<file_id>', methods=['DELETE'])
def delete_file(file_id: str):
    """Delete a file by ID."""
    if storage_engine.delete_file(file_id):
        # Log access
        db_manager.execute_query(
            "INSERT INTO access_logs (file_id, action, ip_address) VALUES (?, ?, ?)",
            (file_id, 'delete', request.remote_addr)
        )
        return jsonify({'message': 'File deleted successfully'}), 200
    else:
        raise NotFound('File not found')


@app.route('/api/files', methods=['GET'])
def list_files():
    """List all files with pagination."""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    offset = (page - 1) * per_page
    
    files = db_manager.execute_query(
        "SELECT * FROM files ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (per_page, offset)
    )
    
    total_files = db_manager.execute_query("SELECT COUNT(*) as count FROM files")
    total_count = total_files[0]['count']
    
    return jsonify({
        'files': files,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total_count,
            'pages': (total_count + per_page - 1) // per_page
        }
    })


@app.route('/api/files/<file_id>/metadata', methods=['GET'])
def get_file_metadata(file_id: str):
    """Get file metadata."""
    files = db_manager.execute_query(
        "SELECT * FROM files WHERE file_id = ?", (file_id,)
    )
    
    if not files:
        raise NotFound('File not found')
    
    return jsonify(files[0])


@app.route('/api/security/scan', methods=['POST'])
def security_scan():
    """Perform security vulnerability scan."""
    scan_result = security_manager.scan_for_vulnerabilities()
    return jsonify(scan_result)


@app.route('/api/config', methods=['GET'])
def get_configuration():
    """Get system configuration."""
    config = db_manager.execute_query("SELECT * FROM configuration")
    return jsonify({
        'configuration': {item['key']: item['value'] for item in config},
        'system_info': {
            'storage_path': app.config['STORAGE_PATH'],
            'max_file_size': app.config['MAX_CONTENT_LENGTH'],
            'api_version': app.config['API_VERSION']
        }
    })


@app.route('/api/config', methods=['POST'])
def update_configuration():
    """Update system configuration."""
    data = request.get_json()
    
    if not data:
        raise BadRequest('No configuration data provided')
    
    for key, value in data.items():
        db_manager.execute_query(
            "INSERT OR REPLACE INTO configuration (key, value) VALUES (?, ?)",
            (key, str(value))
        )
    
    return jsonify({'message': 'Configuration updated successfully'})


@app.route('/api/analytics', methods=['GET'])
def get_analytics():
    """Get usage analytics."""
    # File statistics
    stats = db_manager.execute_query("""
        SELECT 
            COUNT(*) as total_files,
            SUM(size) as total_size,
            AVG(size) as avg_size,
            SUM(access_count) as total_downloads
        FROM files
    """)
    
    # Recent activity
    recent_activity = db_manager.execute_query("""
        SELECT action, COUNT(*) as count
        FROM access_logs
        WHERE timestamp > datetime('now', '-7 days')
        GROUP BY action
    """)
    
    return jsonify({
        'file_statistics': stats[0] if stats else {},
        'recent_activity': recent_activity,
        'uptime_seconds': time.time() - start_time
    })


def get_memory_usage() -> Dict[str, Any]:
    """Get memory usage statistics."""
    try:
        import psutil
        process = psutil.Process()
        memory_info = process.memory_info()
        return {
            'rss_mb': memory_info.rss / 1024 / 1024,
            'vms_mb': memory_info.vms / 1024 / 1024,
            'percent': process.memory_percent()
        }
    except ImportError:
        return {'error': 'psutil not available'}


# Error handlers
@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad request', 'message': str(error)}), 400


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found', 'message': str(error)}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error', 'message': str(error)}), 500


if __name__ == '__main__':
    logger.info("Starting DistributedFS API Server")
    logger.info(f"Storage path: {app.config['STORAGE_PATH']}")
    logger.info(f"Database path: {app.config['DATABASE_PATH']}")
    
    # Run the Flask application
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,
        threaded=True
    ) 