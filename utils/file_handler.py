import os
import tempfile
import hashlib
from typing import Optional, Dict, Any, List
import streamlit as st

class FileHandler:
    def __init__(self):
        self.temp_dir = tempfile.gettempdir()
        self.max_file_size = 100 * 1024 * 1024  # 100MB limit
        self.allowed_extensions = ['.exe', '.dll', '.so', '.bin', '.out', '.elf', '.dylib', '.o', '.obj']
    
    def save_uploaded_file(self, uploaded_file) -> Optional[str]:
        """Save uploaded file to temporary directory"""
        try:
            if uploaded_file is None:
                return None
            
            # Check file size
            if uploaded_file.size > self.max_file_size:
                st.error(f"File too large. Maximum size is {self.max_file_size // (1024*1024)}MB")
                return None
            
            # Create unique filename
            file_hash = hashlib.md5(uploaded_file.name.encode()).hexdigest()[:8]
            temp_filename = f"binary_analysis_{file_hash}_{uploaded_file.name}"
            temp_path = os.path.join(self.temp_dir, temp_filename)
            
            # Write file
            with open(temp_path, 'wb') as f:
                f.write(uploaded_file.getbuffer())
            
            return temp_path
            
        except Exception as e:
            st.error(f"Failed to save file: {str(e)}")
            return None
    
    def validate_file(self, file_path: str) -> Dict[str, Any]:
        """Validate if file is a binary that can be analyzed"""
        try:
            if not os.path.exists(file_path):
                return {'valid': False, 'reason': 'File does not exist'}
            
            # Check file size
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                return {'valid': False, 'reason': 'File is empty'}
            
            if file_size > self.max_file_size:
                return {'valid': False, 'reason': f'File too large (max {self.max_file_size//1024//1024}MB)'}
            
            # Check if file is readable
            try:
                with open(file_path, 'rb') as f:
                    magic = f.read(4)
            except PermissionError:
                return {'valid': False, 'reason': 'Permission denied reading file'}
            
            # Check magic bytes for common binary formats
            valid_magics = [
                b'\x7fELF',  # ELF
                b'MZ',       # PE (first 2 bytes)
                b'\xfe\xed\xfa\xce',  # Mach-O 32-bit big endian
                b'\xce\xfa\xed\xfe',  # Mach-O 32-bit little endian
                b'\xfe\xed\xfa\xcf',  # Mach-O 64-bit big endian
                b'\xcf\xfa\xed\xfe',  # Mach-O 64-bit little endian
            ]
            
            is_binary = False
            detected_format = 'Unknown'
            
            if magic[:4] == b'\x7fELF':
                is_binary = True
                detected_format = 'ELF'
            elif magic[:2] == b'MZ':
                is_binary = True
                detected_format = 'PE'
            elif magic in [b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe', 
                          b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe']:
                is_binary = True
                detected_format = 'Mach-O'
            else:
                # Check if file contains significant binary content
                try:
                    with open(file_path, 'rb') as f:
                        sample = f.read(1024)
                        non_printable = sum(1 for b in sample if b < 32 or b > 126)
                        if len(sample) > 0 and non_printable / len(sample) > 0.3:
                            is_binary = True
                            detected_format = 'Binary (unknown format)'
                except Exception:
                    pass
            
            if is_binary:
                return {
                    'valid': True,
                    'format': detected_format,
                    'size': file_size,
                    'size_human': self._format_size(file_size)
                }
            else:
                return {'valid': False, 'reason': 'File does not appear to be a binary executable'}
                
        except Exception as e:
            return {'valid': False, 'reason': f'Validation error: {str(e)}'}
    
    def cleanup_file(self, file_path: str) -> bool:
        """Remove temporary file"""
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                return True
            return False
        except Exception:
            return False
    
    def get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Get basic file information"""
        try:
            stat = os.stat(file_path)
            return {
                'filename': os.path.basename(file_path),
                'size': stat.st_size,
                'size_human': self._format_size(stat.st_size),
                'permissions': oct(stat.st_mode)[-3:],
                'is_executable': os.access(file_path, os.X_OK),
                'path': file_path
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _format_size(self, size: int) -> str:
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
    
    def is_supported_format(self, filename: str) -> bool:
        """Check if file extension is supported"""
        if not filename:
            return False
        
        # Get file extension
        _, ext = os.path.splitext(filename.lower())
        
        # Allow files without extensions (common for Unix binaries)
        if not ext:
            return True
        
        return ext in self.allowed_extensions
    
    def get_supported_extensions(self) -> List[str]:
        """Get list of supported file extensions"""
        return self.allowed_extensions.copy()
