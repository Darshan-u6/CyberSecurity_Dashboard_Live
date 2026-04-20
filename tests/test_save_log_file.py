import sys
import os
from unittest.mock import MagicMock, patch, mock_open

# Mock dependencies that are not available in the environment
mock_modules = [
    'fastapi', 'fastapi.responses', 'fastapi.middleware.cors', 'fastapi.staticfiles',
    'fastapi.security', 'pydantic', 'mysql', 'mysql.connector', 'fpdf', 'passlib', 'passlib.context',
    'ldap3', 'ldap3.utils', 'ldap3.utils.conv', 'uvicorn', 'requests', 'scapy', 'scapy.all', 'jose', 'starlette', 'starlette.middleware.base', 'packaging'
]

for module in mock_modules:
    if module not in sys.modules:
        m = MagicMock()
        sys.modules[module] = m
        # Special handling for packages
        if module in ['ldap3', 'mysql', 'fastapi', 'passlib', 'scapy', 'starlette']:
            m.__path__ = []

from main import save_log_file

@patch('main.os.makedirs')
@patch('builtins.open', new_callable=mock_open)
def test_save_log_file_success(mock_file, mock_makedirs):
    filename = "test_log.txt"
    content = "test content"

    save_log_file(filename, content)

    mock_makedirs.assert_called_once_with("logs", exist_ok=True)
    expected_path = os.path.join("logs", filename)
    mock_file.assert_called_once_with(expected_path, "w")
    mock_file().write.assert_called_once_with(content)

@patch('main.os.makedirs')
@patch('builtins.print')
def test_save_log_file_exception_makedirs(mock_print, mock_makedirs):
    mock_makedirs.side_effect = Exception("Permission denied")

    save_log_file("test.txt", "content")

    mock_print.assert_called_once_with("Error saving log file: Permission denied")

@patch('main.os.makedirs')
@patch('builtins.open', new_callable=mock_open)
@patch('builtins.print')
def test_save_log_file_exception_open(mock_print, mock_file, mock_makedirs):
    mock_file.side_effect = Exception("Disk full")

    save_log_file("test.txt", "content")

    mock_print.assert_called_once_with("Error saving log file: Disk full")
