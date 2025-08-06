import os
import struct
import hashlib
import math
from typing import Dict, Any, List, Optional
import subprocess
import tempfile

class BinaryAnalyzer:
    def __init__(self):
        self.supported_formats = ['ELF', 'PE', 'Mach-O']
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Main analysis function that coordinates all analysis tasks"""
        try:
            results = {
                'file_info': self._get_file_info(file_path),
                'entropy': self._calculate_entropy(file_path),
                'strings': self._extract_strings(file_path),
                'file_format': self._detect_format(file_path),
                'architecture': self._detect_architecture(file_path),
                'file_size': os.path.getsize(file_path),
                'hashes': self._calculate_hashes(file_path)
            }
            
            # Add format-specific analysis
            file_format = results['file_format']
            if file_format == 'ELF':
                results.update(self._analyze_elf(file_path))
            elif file_format == 'PE':
                results.update(self._analyze_pe(file_path))
            elif file_format == 'Mach-O':
                results.update(self._analyze_macho(file_path))
            
            return results
            
        except Exception as e:
            return {'error': f"Analysis failed: {str(e)}"}
    
    def _get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Extract basic file information"""
        try:
            stat = os.stat(file_path)
            return {
                'filename': os.path.basename(file_path),
                'size': stat.st_size,
                'size_human': self._format_size(stat.st_size),
                'permissions': oct(stat.st_mode)[-3:],
                'is_executable': os.access(file_path, os.X_OK)
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _calculate_entropy(self, file_path: str) -> float:
        """Calculate Shannon entropy of the file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if not data:
                return 0.0
            
            # Count byte frequencies
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Calculate entropy
            entropy = 0.0
            data_len = len(data)
            for count in byte_counts:
                if count > 0:
                    p = count / data_len
                    entropy -= p * math.log2(p)
            
            return round(entropy, 4)
        except Exception:
            return 0.0
    
    def _extract_strings(self, file_path: str, min_length: int = 4) -> List[str]:
        """Extract readable strings from binary"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            strings = []
            current_string = ""
            
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += chr(byte)
                else:
                    if len(current_string) >= min_length:
                        strings.append(current_string)
                    current_string = ""
            
            # Don't forget the last string
            if len(current_string) >= min_length:
                strings.append(current_string)
            
            # Limit to first 1000 strings to avoid memory issues
            return strings[:1000]
        except Exception:
            return []
    
    def _detect_format(self, file_path: str) -> str:
        """Detect binary format based on magic bytes"""
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
            
            if magic[:4] == b'\x7fELF':
                return 'ELF'
            elif magic[:2] == b'MZ':
                return 'PE'
            elif magic == b'\xfe\xed\xfa\xce' or magic == b'\xce\xfa\xed\xfe':
                return 'Mach-O'
            elif magic == b'\xfe\xed\xfa\xcf' or magic == b'\xcf\xfa\xed\xfe':
                return 'Mach-O'
            else:
                return 'Unknown'
        except Exception:
            return 'Unknown'
    
    def _detect_architecture(self, file_path: str) -> str:
        """Detect target architecture"""
        try:
            file_format = self._detect_format(file_path)
            
            if file_format == 'ELF':
                return self._detect_elf_arch(file_path)
            elif file_format == 'PE':
                return self._detect_pe_arch(file_path)
            elif file_format == 'Mach-O':
                return self._detect_macho_arch(file_path)
            else:
                return 'Unknown'
        except Exception:
            return 'Unknown'
    
    def _detect_elf_arch(self, file_path: str) -> str:
        """Detect ELF architecture"""
        try:
            with open(file_path, 'rb') as f:
                f.seek(4)  # Skip magic
                ei_class = f.read(1)[0]
                f.seek(18)  # e_machine offset
                e_machine = struct.unpack('<H', f.read(2))[0]
            
            arch_map = {
                0x3E: 'x86-64',
                0x03: 'i386',
                0x28: 'ARM',
                0xB7: 'AArch64',
                0x08: 'MIPS',
                0xF3: 'RISC-V'
            }
            
            arch = arch_map.get(e_machine, f'Unknown (0x{e_machine:02x})')
            if ei_class == 1:
                arch += ' (32-bit)'
            elif ei_class == 2:
                arch += ' (64-bit)'
            
            return arch
        except Exception:
            return 'Unknown'
    
    def _detect_pe_arch(self, file_path: str) -> str:
        """Detect PE architecture"""
        try:
            with open(file_path, 'rb') as f:
                f.seek(60)  # e_lfanew offset
                pe_offset = struct.unpack('<L', f.read(4))[0]
                f.seek(pe_offset + 4)  # Skip PE signature
                machine = struct.unpack('<H', f.read(2))[0]
            
            machine_map = {
                0x014c: 'i386',
                0x8664: 'x86-64',
                0x01c0: 'ARM',
                0xaa64: 'AArch64'
            }
            
            return machine_map.get(machine, f'Unknown (0x{machine:02x})')
        except Exception:
            return 'Unknown'
    
    def _detect_macho_arch(self, file_path: str) -> str:
        """Detect Mach-O architecture"""
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                if magic in [b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe']:
                    # 32-bit
                    cputype = struct.unpack('<L' if magic == b'\xce\xfa\xed\xfe' else '>L', f.read(4))[0]
                    return f'32-bit (CPU type: {cputype})'
                elif magic in [b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe']:
                    # 64-bit
                    cputype = struct.unpack('<L' if magic == b'\xcf\xfa\xed\xfe' else '>L', f.read(4))[0]
                    
                    cpu_map = {
                        0x01000007: 'x86-64',
                        0x0100000C: 'AArch64'
                    }
                    
                    return cpu_map.get(cputype, f'64-bit (CPU type: {cputype})')
            
            return 'Unknown'
        except Exception:
            return 'Unknown'
    
    def _calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate various hashes of the file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            return {
                'md5': hashlib.md5(data).hexdigest(),
                'sha1': hashlib.sha1(data).hexdigest(),
                'sha256': hashlib.sha256(data).hexdigest()
            }
        except Exception:
            return {}
    
    def _analyze_elf(self, file_path: str) -> Dict[str, Any]:
        """ELF-specific analysis"""
        try:
            # Use readelf if available
            result = subprocess.run(['readelf', '-h', file_path], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return {'elf_header': result.stdout}
            else:
                return {'elf_analysis': 'readelf not available or failed'}
        except Exception as e:
            return {'elf_analysis': f'Analysis failed: {str(e)}'}
    
    def _analyze_pe(self, file_path: str) -> Dict[str, Any]:
        """PE-specific analysis"""
        try:
            # Basic PE analysis without external tools
            with open(file_path, 'rb') as f:
                f.seek(60)
                pe_offset = struct.unpack('<L', f.read(4))[0]
                f.seek(pe_offset)
                pe_sig = f.read(4)
                
                if pe_sig == b'PE\x00\x00':
                    return {'pe_signature': 'Valid PE signature found'}
                else:
                    return {'pe_signature': 'Invalid PE signature'}
        except Exception as e:
            return {'pe_analysis': f'Analysis failed: {str(e)}'}
    
    def _analyze_macho(self, file_path: str) -> Dict[str, Any]:
        """Mach-O specific analysis"""
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                if magic in [b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe', 
                            b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe']:
                    return {'macho_signature': 'Valid Mach-O signature found'}
                else:
                    return {'macho_signature': 'Invalid Mach-O signature'}
        except Exception as e:
            return {'macho_analysis': f'Analysis failed: {str(e)}'}
    
    def _format_size(self, size: int) -> str:
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
