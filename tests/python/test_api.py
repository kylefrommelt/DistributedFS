#!/usr/bin/env python3
"""
Comprehensive test suite for DistributedFS REST API
Tests all endpoints, error handling, and integration with storage engine.
"""

import pytest
import json
import tempfile
import os
import shutil
from unittest.mock import patch, MagicMock
import sqlite3
from io import BytesIO

# Import the Flask app
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'python'))

from app import app, db_manager, security_manager, storage_engine


class TestDistributedFSAPI:
    """Test suite for DistributedFS REST API"""

    @pytest.fixture(autouse=True)
    def setup_test_environment(self):
        """Set up test environment before each test"""
        self.test_dir = tempfile.mkdtemp()
        self.test_db = os.path.join(self.test_dir, 'test.db')
        self.test_storage = os.path.join(self.test_dir, 'storage')
        
        # Configure app for testing
        app.config['TESTING'] = True
        app.config['DATABASE_PATH'] = self.test_db
        app.config['STORAGE_PATH'] = self.test_storage
        app.config['WTF_CSRF_ENABLED'] = False
        
        os.makedirs(self.test_storage, exist_ok=True)
        
        # Create test client
        self.client = app.test_client()
        
        # Initialize test database
        self.init_test_database()
        
        yield
        
        # Clean up
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def init_test_database(self):
        """Initialize test database with sample data"""
        conn = sqlite3.connect(self.test_db)
        cursor = conn.cursor()
        
        # Create tables
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
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS access_logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id TEXT,
                user_id TEXT,
                action TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS configuration (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()

    def test_health_check(self):
        """Test system health check endpoint"""
        response = self.client.get('/api/health')
        assert response.status_code == 200
        
        data = response.get_json()
        assert 'status' in data
        assert 'version' in data
        assert 'timestamp' in data
        assert 'storage_stats' in data
        assert data['status'] in ['healthy', 'unhealthy']

    def test_file_upload_and_download(self):
        """Test file upload and download functionality"""
        # Test file upload
        test_content = b'This is a test file content'
        test_filename = 'test_file.txt'
        
        response = self.client.post(
            '/api/files',
            data={'file': (BytesIO(test_content), test_filename)},
            content_type='multipart/form-data'
        )
        
        assert response.status_code == 201
        upload_data = response.get_json()
        assert 'file_id' in upload_data
        assert upload_data['filename'] == test_filename
        assert upload_data['size'] == len(test_content)
        
        file_id = upload_data['file_id']
        
        # Test file download
        response = self.client.get(f'/api/files/{file_id}')
        assert response.status_code == 200
        assert response.data == test_content
        assert 'attachment' in response.headers['Content-Disposition']

    def test_file_upload_validation(self):
        """Test file upload validation"""
        # Test missing file
        response = self.client.post('/api/files', data={})
        assert response.status_code == 400
        
        # Test empty filename
        response = self.client.post(
            '/api/files',
            data={'file': (BytesIO(b'content'), '')},
            content_type='multipart/form-data'
        )
        assert response.status_code == 400

    def test_file_not_found(self):
        """Test handling of non-existent file requests"""
        response = self.client.get('/api/files/non_existent_id')
        assert response.status_code == 404
        
        response = self.client.delete('/api/files/non_existent_id')
        assert response.status_code == 404

    def test_file_deletion(self):
        """Test file deletion functionality"""
        # Upload a file first
        test_content = b'File to be deleted'
        response = self.client.post(
            '/api/files',
            data={'file': (BytesIO(test_content), 'delete_test.txt')},
            content_type='multipart/form-data'
        )
        
        assert response.status_code == 201
        file_id = response.get_json()['file_id']
        
        # Delete the file
        response = self.client.delete(f'/api/files/{file_id}')
        assert response.status_code == 200
        
        # Verify file is deleted
        response = self.client.get(f'/api/files/{file_id}')
        assert response.status_code == 404

    def test_list_files(self):
        """Test file listing with pagination"""
        # Upload multiple files
        file_ids = []
        for i in range(5):
            content = f'File {i} content'.encode()
            response = self.client.post(
                '/api/files',
                data={'file': (BytesIO(content), f'file_{i}.txt')},
                content_type='multipart/form-data'
            )
            assert response.status_code == 201
            file_ids.append(response.get_json()['file_id'])
        
        # Test listing files
        response = self.client.get('/api/files')
        assert response.status_code == 200
        
        data = response.get_json()
        assert 'files' in data
        assert 'pagination' in data
        assert len(data['files']) == 5
        
        # Test pagination
        response = self.client.get('/api/files?page=1&per_page=2')
        assert response.status_code == 200
        
        data = response.get_json()
        assert len(data['files']) == 2
        assert data['pagination']['page'] == 1
        assert data['pagination']['per_page'] == 2

    def test_file_metadata(self):
        """Test file metadata retrieval"""
        # Upload a file
        test_content = b'Metadata test content'
        response = self.client.post(
            '/api/files',
            data={'file': (BytesIO(test_content), 'metadata_test.txt')},
            content_type='multipart/form-data'
        )
        
        assert response.status_code == 201
        file_id = response.get_json()['file_id']
        
        # Get metadata
        response = self.client.get(f'/api/files/{file_id}/metadata')
        assert response.status_code == 200
        
        metadata = response.get_json()
        assert metadata['file_id'] == file_id
        assert metadata['filename'] == 'metadata_test.txt'
        assert metadata['size'] == len(test_content)
        assert 'checksum' in metadata
        assert 'created_at' in metadata

    def test_security_scan(self):
        """Test security vulnerability scanning"""
        response = self.client.post('/api/security/scan')
        assert response.status_code == 200
        
        data = response.get_json()
        assert 'has_vulnerabilities' in data
        assert 'cve_ids' in data
        assert 'recommendations' in data
        assert 'scan_time' in data
        assert 'scanned_components' in data

    def test_configuration_management(self):
        """Test configuration get and update"""
        # Get configuration
        response = self.client.get('/api/config')
        assert response.status_code == 200
        
        data = response.get_json()
        assert 'configuration' in data
        assert 'system_info' in data
        
        # Update configuration
        config_data = {
            'max_file_size': '2048',
            'compression_enabled': 'true'
        }
        
        response = self.client.post(
            '/api/config',
            data=json.dumps(config_data),
            content_type='application/json'
        )
        assert response.status_code == 200
        
        # Verify configuration updated
        response = self.client.get('/api/config')
        assert response.status_code == 200
        
        data = response.get_json()
        assert data['configuration']['max_file_size'] == '2048'
        assert data['configuration']['compression_enabled'] == 'true'

    def test_configuration_validation(self):
        """Test configuration update validation"""
        # Test empty configuration data
        response = self.client.post('/api/config', data='')
        assert response.status_code == 400

    def test_analytics_endpoint(self):
        """Test analytics data retrieval"""
        # Upload some files to generate analytics data
        for i in range(3):
            content = f'Analytics test file {i}'.encode()
            self.client.post(
                '/api/files',
                data={'file': (BytesIO(content), f'analytics_{i}.txt')},
                content_type='multipart/form-data'
            )
        
        response = self.client.get('/api/analytics')
        assert response.status_code == 200
        
        data = response.get_json()
        assert 'file_statistics' in data
        assert 'recent_activity' in data
        assert 'uptime_seconds' in data

    def test_error_handling(self):
        """Test error handling for various scenarios"""
        # Test 404 for non-existent endpoints
        response = self.client.get('/api/nonexistent')
        assert response.status_code == 404
        
        # Test malformed JSON
        response = self.client.post(
            '/api/config',
            data='invalid json',
            content_type='application/json'
        )
        assert response.status_code == 400

    def test_large_file_handling(self):
        """Test handling of large files"""
        # Create large file content (1MB)
        large_content = b'x' * (1024 * 1024)
        
        response = self.client.post(
            '/api/files',
            data={'file': (BytesIO(large_content), 'large_file.bin')},
            content_type='multipart/form-data'
        )
        
        assert response.status_code == 201
        file_id = response.get_json()['file_id']
        
        # Test download of large file
        response = self.client.get(f'/api/files/{file_id}')
        assert response.status_code == 200
        assert len(response.data) == len(large_content)

    @patch('app.security_manager.scan_for_vulnerabilities')
    def test_security_scan_with_vulnerabilities(self, mock_scan):
        """Test security scan when vulnerabilities are found"""
        mock_scan.return_value = {
            'has_vulnerabilities': True,
            'cve_ids': ['CVE-2022-0001', 'CVE-2022-0002'],
            'recommendations': ['Update package X', 'Update package Y'],
            'scan_time': '2023-01-01T00:00:00',
            'scanned_components': ['python', 'flask']
        }
        
        response = self.client.post('/api/security/scan')
        assert response.status_code == 200
        
        data = response.get_json()
        assert data['has_vulnerabilities'] is True
        assert len(data['cve_ids']) == 2
        assert len(data['recommendations']) == 2

    def test_concurrent_file_operations(self):
        """Test concurrent file operations"""
        import threading
        import time
        
        results = []
        errors = []
        
        def upload_file(file_num):
            try:
                content = f'Concurrent file {file_num}'.encode()
                response = self.client.post(
                    '/api/files',
                    data={'file': (BytesIO(content), f'concurrent_{file_num}.txt')},
                    content_type='multipart/form-data'
                )
                results.append(response.status_code)
            except Exception as e:
                errors.append(str(e))
        
        # Create multiple threads for concurrent uploads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=upload_file, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify all uploads were successful
        assert len(errors) == 0
        assert all(status == 201 for status in results)

    def test_api_response_format(self):
        """Test that API responses have consistent format"""
        # Test health endpoint response format
        response = self.client.get('/api/health')
        data = response.get_json()
        
        required_fields = ['status', 'version', 'timestamp', 'storage_stats']
        for field in required_fields:
            assert field in data
        
        # Test file upload response format
        content = b'Response format test'
        response = self.client.post(
            '/api/files',
            data={'file': (BytesIO(content), 'format_test.txt')},
            content_type='multipart/form-data'
        )
        
        data = response.get_json()
        required_fields = ['file_id', 'filename', 'size', 'checksum', 'uploaded_at']
        for field in required_fields:
            assert field in data

    def test_file_access_logging(self):
        """Test that file access is properly logged"""
        # Upload a file
        content = b'Access logging test'
        response = self.client.post(
            '/api/files',
            data={'file': (BytesIO(content), 'access_test.txt')},
            content_type='multipart/form-data'
        )
        
        file_id = response.get_json()['file_id']
        
        # Download the file
        self.client.get(f'/api/files/{file_id}')
        
        # Check access logs
        conn = sqlite3.connect(self.test_db)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM access_logs WHERE file_id = ?", (file_id,))
        logs = cursor.fetchall()
        conn.close()
        
        # Should have upload and download logs
        assert len(logs) >= 2
        actions = [log[3] for log in logs]  # action is 4th column
        assert 'upload' in actions
        assert 'download' in actions


if __name__ == '__main__':
    pytest.main([__file__, '-v']) 