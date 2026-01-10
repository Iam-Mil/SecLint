import pytest
import tempfile
from pathlib import Path


@pytest.fixture
def temp_dir():
    """Creates a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_py_file(temp_dir):
    """Creates a sample Python file."""
    file_path = temp_dir / "sample.py"
    file_path.write_text("print('Hello World')")
    return file_path


@pytest.fixture
def vulnerable_code_file(temp_dir):
    """Creates a file with vulnerable code."""
    file_path = temp_dir / "vulnerable.py"
    code = """
import os

# Dangerous functions
eval("print('test')")
exec("import sys")

# Weak crypto
import hashlib
hashlib.md5(b"test")

# Hardcoded secret
api_key = "AKIAIOSFODNN7EXAMPLE"
"""
    file_path.write_text(code)
    return file_path
