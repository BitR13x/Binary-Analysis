import struct
import subprocess
from typing import Dict, Any, List
import tempfile
import os

class SecurityFeaturesAnalyzer:
    def __init__(self):
        self.security_features = [
            'stack_canary', 'nx_bit', 'aslr', 'pie', 'relro',
            'fortify_source', 'dep', 'cfg', 'cet'
        ]
    
    def analyze_security_features(self, file_path: str, file_format: str) -> Dict[str, Any]:
        """Analyze security features of the binary"""
        try:
            if file_format == 'ELF':
                return self._analyze_elf_security(file_path)
            elif file_format == 'PE':
                return self._analyze_pe_security(file_path)
            elif file_format == 'Mach-O':
                return self._analyze_macho_security(file_path)
            else:
                return {'error': f'Unsupported format: {file_format}'}
                
        except Exception as e:
            return {'error': f'Security analysis failed: {str(e)}'}
    
    def _analyze_elf_security(self, file_path: str) -> Dict[str, Any]:
        """Analyze ELF security features"""
        features = {
            'stack_canary': self._check_elf_stack_canary(file_path),
            'nx_bit': self._check_elf_nx_bit(file_path),
            'aslr': self._check_elf_aslr(file_path),
            'pie': self._check_elf_pie(file_path),
            'relro': self._check_elf_relro(file_path),
            'fortify_source': self._check_elf_fortify(file_path),
            'rpath': self._check_elf_rpath(file_path)
        }
        
        # Calculate security score
        security_score = self._calculate_security_score(features)
        
        return {
            'features': features,
            'security_score': security_score,
            'recommendations': self._generate_security_recommendations(features)
        }
    
    def _analyze_pe_security(self, file_path: str) -> Dict[str, Any]:
        """Analyze PE security features"""
        features = {
            'dep': self._check_pe_dep(file_path),
            'aslr': self._check_pe_aslr(file_path),
            'cfg': self._check_pe_cfg(file_path),
            'seh': self._check_pe_seh(file_path),
            'safe_seh': self._check_pe_safe_seh(file_path),
            'gs_check': self._check_pe_gs(file_path),
            'authenticode': self._check_pe_authenticode(file_path)
        }
        
        security_score = self._calculate_security_score(features)
        
        return {
            'features': features,
            'security_score': security_score,
            'recommendations': self._generate_security_recommendations(features)
        }
    
    def _analyze_macho_security(self, file_path: str) -> Dict[str, Any]:
        """Analyze Mach-O security features"""
        features = {
            'pie': self._check_macho_pie(file_path),
            'nx_bit': self._check_macho_nx(file_path),
            'stack_canary': self._check_macho_stack_canary(file_path),
            'arc': self._check_macho_arc(file_path),
            'code_signature': self._check_macho_signature(file_path),
            'entitlements': self._check_macho_entitlements(file_path)
        }
        
        security_score = self._calculate_security_score(features)
        
        return {
            'features': features,
            'security_score': security_score,
            'recommendations': self._generate_security_recommendations(features)
        }
    
    # ELF Security Checks
    def _check_elf_stack_canary(self, file_path: str) -> Dict[str, Any]:
        """Check for stack canary protection"""
        try:
            result = subprocess.run(['readelf', '-s', file_path], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                output = result.stdout
                canary_symbols = ['__stack_chk_fail', '__stack_chk_guard', '__intel_security_cookie']
                has_canary = any(symbol in output for symbol in canary_symbols)
                
                return {
                    'enabled': has_canary,
                    'details': 'Stack canary symbols found' if has_canary else 'No stack canary symbols found',
                    'symbols_found': [s for s in canary_symbols if s in output]
                }
            else:
                return {'enabled': False, 'details': 'Could not determine (readelf failed)'}
        except Exception:
            # Fallback: check for stack canary strings
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                has_canary = b'__stack_chk_fail' in data or b'__stack_chk_guard' in data
                return {
                    'enabled': has_canary,
                    'details': 'Stack canary strings found' if has_canary else 'No stack canary strings found'
                }
            except Exception:
                return {'enabled': False, 'details': 'Could not determine'}
    
    def _check_elf_nx_bit(self, file_path: str) -> Dict[str, Any]:
        """Check for NX bit (Non-eXecutable stack)"""
        try:
            result = subprocess.run(['readelf', '-l', file_path], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                output = result.stdout
                # Look for GNU_STACK segment
                if 'GNU_STACK' in output:
                    # Check if RWE (no NX) or RW (NX enabled)
                    lines = output.split('\n')
                    for line in lines:
                        if 'GNU_STACK' in line and 'RWE' in line:
                            return {'enabled': False, 'details': 'Stack is executable (RWE)'}
                        elif 'GNU_STACK' in line and 'RW' in line:
                            return {'enabled': True, 'details': 'Stack is non-executable (RW)'}
                    
                return {'enabled': True, 'details': 'GNU_STACK segment present'}
            else:
                return {'enabled': False, 'details': 'Could not determine (readelf failed)'}
        except Exception:
            return {'enabled': False, 'details': 'Could not determine'}
    
    def _check_elf_aslr(self, file_path: str) -> Dict[str, Any]:
        """Check if binary supports ASLR"""
        try:
            result = subprocess.run(['readelf', '-h', file_path], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                output = result.stdout
                # ASLR is supported if it's a shared object or PIE
                if 'DYN (Shared object file)' in output or 'DYN (Position-Independent Executable file)' in output:
                    return {'enabled': True, 'details': 'Position independent binary (supports ASLR)'}
                else:
                    return {'enabled': False, 'details': 'Static binary (limited ASLR support)'}
            else:
                return {'enabled': False, 'details': 'Could not determine (readelf failed)'}
        except Exception:
            return {'enabled': False, 'details': 'Could not determine'}
    
    def _check_elf_pie(self, file_path: str) -> Dict[str, Any]:
        """Check for Position Independent Executable"""
        try:
            result = subprocess.run(['readelf', '-h', file_path], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                output = result.stdout
                if 'DYN (Position-Independent Executable file)' in output:
                    return {'enabled': True, 'details': 'PIE enabled'}
                elif 'EXEC (Executable file)' in output:
                    return {'enabled': False, 'details': 'Not PIE (static executable)'}
                else:
                    return {'enabled': False, 'details': 'Unknown executable type'}
            else:
                return {'enabled': False, 'details': 'Could not determine (readelf failed)'}
        except Exception:
            return {'enabled': False, 'details': 'Could not determine'}
    
    def _check_elf_relro(self, file_path: str) -> Dict[str, Any]:
        """Check for RELRO (RELocation Read-Only)"""
        try:
            result = subprocess.run(['readelf', '-l', file_path], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                output = result.stdout
                if 'GNU_RELRO' in output:
                    # Check for full RELRO
                    result2 = subprocess.run(['readelf', '-d', file_path], 
                                           capture_output=True, text=True, timeout=30)
                    if result2.returncode == 0 and 'BIND_NOW' in result2.stdout:
                        return {'enabled': True, 'details': 'Full RELRO enabled'}
                    else:
                        return {'enabled': True, 'details': 'Partial RELRO enabled'}
                else:
                    return {'enabled': False, 'details': 'No RELRO'}
            else:
                return {'enabled': False, 'details': 'Could not determine (readelf failed)'}
        except Exception:
            return {'enabled': False, 'details': 'Could not determine'}
    
    def _check_elf_fortify(self, file_path: str) -> Dict[str, Any]:
        """Check for FORTIFY_SOURCE"""
        try:
            result = subprocess.run(['readelf', '-s', file_path], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                output = result.stdout
                fortified_functions = ['__strcpy_chk', '__memcpy_chk', '__sprintf_chk']
                found_functions = [f for f in fortified_functions if f in output]
                
                if found_functions:
                    return {
                        'enabled': True, 
                        'details': f'FORTIFY_SOURCE enabled ({len(found_functions)} fortified functions)',
                        'functions': found_functions
                    }
                else:
                    return {'enabled': False, 'details': 'No fortified functions found'}
            else:
                return {'enabled': False, 'details': 'Could not determine (readelf failed)'}
        except Exception:
            return {'enabled': False, 'details': 'Could not determine'}
    
    def _check_elf_rpath(self, file_path: str) -> Dict[str, Any]:
        """Check for dangerous RPATH/RUNPATH"""
        try:
            result = subprocess.run(['readelf', '-d', file_path], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                output = result.stdout
                dangerous_paths = ['.', '$ORIGIN', '/tmp', '/var/tmp']
                
                if 'RPATH' in output or 'RUNPATH' in output:
                    lines = output.split('\n')
                    rpaths = []
                    for line in lines:
                        if 'RPATH' in line or 'RUNPATH' in line:
                            rpaths.append(line.strip())
                    
                    # Check for dangerous paths
                    has_dangerous = any(path in str(rpaths) for path in dangerous_paths)
                    
                    return {
                        'enabled': not has_dangerous,  # Safe if no dangerous paths
                        'details': f'RPATH/RUNPATH found: {rpaths}',
                        'safe': not has_dangerous
                    }
                else:
                    return {'enabled': True, 'details': 'No RPATH/RUNPATH (safe)'}
            else:
                return {'enabled': True, 'details': 'Could not determine (assuming safe)'}
        except Exception:
            return {'enabled': True, 'details': 'Could not determine (assuming safe)'}
    
    # PE Security Checks
    def _check_pe_dep(self, file_path: str) -> Dict[str, Any]:
        """Check for DEP (Data Execution Prevention)"""
        try:
            with open(file_path, 'rb') as f:
                f.seek(60)  # e_lfanew
                pe_offset = struct.unpack('<L', f.read(4))[0]
                f.seek(pe_offset + 24)  # Skip PE signature and file header
                
                # Read optional header
                f.seek(pe_offset + 24 + 16)  # DllCharacteristics offset in optional header
                dll_characteristics = struct.unpack('<H', f.read(2))[0]
                
                # Check NX_COMPAT flag (0x0100)
                dep_enabled = bool(dll_characteristics & 0x0100)
                
                return {
                    'enabled': dep_enabled,
                    'details': 'DEP enabled' if dep_enabled else 'DEP not enabled'
                }
        except Exception:
            return {'enabled': False, 'details': 'Could not determine'}
    
    def _check_pe_aslr(self, file_path: str) -> Dict[str, Any]:
        """Check for ASLR support in PE"""
        try:
            with open(file_path, 'rb') as f:
                f.seek(60)  # e_lfanew
                pe_offset = struct.unpack('<L', f.read(4))[0]
                f.seek(pe_offset + 24 + 16)  # DllCharacteristics offset
                dll_characteristics = struct.unpack('<H', f.read(2))[0]
                
                # Check DYNAMIC_BASE flag (0x0040)
                aslr_enabled = bool(dll_characteristics & 0x0040)
                
                return {
                    'enabled': aslr_enabled,
                    'details': 'ASLR enabled' if aslr_enabled else 'ASLR not enabled'
                }
        except Exception:
            return {'enabled': False, 'details': 'Could not determine'}
    
    def _check_pe_cfg(self, file_path: str) -> Dict[str, Any]:
        """Check for Control Flow Guard"""
        try:
            with open(file_path, 'rb') as f:
                f.seek(60)
                pe_offset = struct.unpack('<L', f.read(4))[0]
                f.seek(pe_offset + 24 + 16)
                dll_characteristics = struct.unpack('<H', f.read(2))[0]
                
                # Check GUARD_CF flag (0x4000)
                cfg_enabled = bool(dll_characteristics & 0x4000)
                
                return {
                    'enabled': cfg_enabled,
                    'details': 'Control Flow Guard enabled' if cfg_enabled else 'CFG not enabled'
                }
        except Exception:
            return {'enabled': False, 'details': 'Could not determine'}
    
    def _check_pe_seh(self, file_path: str) -> Dict[str, Any]:
        """Check for SEH (Structured Exception Handling)"""
        # This is a basic check - more sophisticated analysis would require parsing the exception directory
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                # Look for SEH-related strings
                seh_indicators = [b'_except_handler', b'__security_cookie', b'_SEH_']
                has_seh = any(indicator in data for indicator in seh_indicators)
                
                return {
                    'enabled': has_seh,
                    'details': 'SEH indicators found' if has_seh else 'No SEH indicators found'
                }
        except Exception:
            return {'enabled': False, 'details': 'Could not determine'}
    
    def _check_pe_safe_seh(self, file_path: str) -> Dict[str, Any]:
        """Check for Safe SEH"""
        # This requires parsing the load config directory - simplified check
        return {'enabled': False, 'details': 'Safe SEH check not implemented'}
    
    def _check_pe_gs(self, file_path: str) -> Dict[str, Any]:
        """Check for /GS (buffer security check)"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                # Look for GS-related symbols
                gs_indicators = [b'__security_cookie', b'__security_check_cookie', b'__report_gsfailure']
                has_gs = any(indicator in data for indicator in gs_indicators)
                
                return {
                    'enabled': has_gs,
                    'details': '/GS buffer security check enabled' if has_gs else 'No /GS indicators found'
                }
        except Exception:
            return {'enabled': False, 'details': 'Could not determine'}
    
    def _check_pe_authenticode(self, file_path: str) -> Dict[str, Any]:
        """Check for Authenticode signature"""
        # This would require parsing the certificate table - simplified check
        try:
            with open(file_path, 'rb') as f:
                f.seek(60)
                pe_offset = struct.unpack('<L', f.read(4))[0]
                f.read(4)  # PE signature
                f.read(20)  # File header
                
                # Read optional header magic
                magic = struct.unpack('<H', f.read(2))[0]
                
                if magic == 0x20b:  # PE32+
                    f.seek(pe_offset + 24 + 128)  # Certificate table offset for PE32+
                else:  # PE32
                    f.seek(pe_offset + 24 + 128)  # Certificate table offset for PE32
                
                cert_addr = struct.unpack('<L', f.read(4))[0]
                cert_size = struct.unpack('<L', f.read(4))[0]
                
                has_cert = cert_addr != 0 and cert_size != 0
                
                return {
                    'enabled': has_cert,
                    'details': 'Authenticode signature present' if has_cert else 'No Authenticode signature'
                }
        except Exception:
            return {'enabled': False, 'details': 'Could not determine'}
    
    # Mach-O Security Checks
    def _check_macho_pie(self, file_path: str) -> Dict[str, Any]:
        """Check for PIE in Mach-O"""
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                if magic in [b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe',
                            b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe']:
                    f.seek(12)  # Skip to flags
                    flags = struct.unpack('<L', f.read(4))[0]
                    
                    # Check MH_PIE flag (0x200000)
                    pie_enabled = bool(flags & 0x200000)
                    
                    return {
                        'enabled': pie_enabled,
                        'details': 'PIE enabled' if pie_enabled else 'PIE not enabled'
                    }
                
                return {'enabled': False, 'details': 'Not a valid Mach-O file'}
        except Exception:
            return {'enabled': False, 'details': 'Could not determine'}
    
    def _check_macho_nx(self, file_path: str) -> Dict[str, Any]:
        """Check for NX bit in Mach-O"""
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                if magic in [b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe',
                            b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe']:
                    f.seek(12)
                    flags = struct.unpack('<L', f.read(4))[0]
                    
                    # Check MH_NO_HEAP_EXECUTION flag (0x1000000)
                    nx_enabled = bool(flags & 0x1000000)
                    
                    return {
                        'enabled': nx_enabled,
                        'details': 'NX bit enabled' if nx_enabled else 'NX bit not set'
                    }
                
                return {'enabled': False, 'details': 'Not a valid Mach-O file'}
        except Exception:
            return {'enabled': False, 'details': 'Could not determine'}
    
    def _check_macho_stack_canary(self, file_path: str) -> Dict[str, Any]:
        """Check for stack canary in Mach-O"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                # Look for stack canary symbols
                canary_symbols = [b'___stack_chk_fail', b'___stack_chk_guard']
                has_canary = any(symbol in data for symbol in canary_symbols)
                
                return {
                    'enabled': has_canary,
                    'details': 'Stack canary symbols found' if has_canary else 'No stack canary symbols found'
                }
        except Exception:
            return {'enabled': False, 'details': 'Could not determine'}
    
    def _check_macho_arc(self, file_path: str) -> Dict[str, Any]:
        """Check for ARC (Automatic Reference Counting)"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                # Look for ARC-related symbols
                arc_symbols = [b'objc_retain', b'objc_release', b'objc_autorelease']
                has_arc = any(symbol in data for symbol in arc_symbols)
                
                return {
                    'enabled': has_arc,
                    'details': 'ARC symbols found' if has_arc else 'No ARC symbols found'
                }
        except Exception:
            return {'enabled': False, 'details': 'Could not determine'}
    
    def _check_macho_signature(self, file_path: str) -> Dict[str, Any]:
        """Check for code signature"""
        # This would require parsing the load commands - simplified check
        return {'enabled': False, 'details': 'Code signature check not implemented'}
    
    def _check_macho_entitlements(self, file_path: str) -> Dict[str, Any]:
        """Check for entitlements"""
        # This would require parsing entitlements - simplified check
        return {'enabled': False, 'details': 'Entitlements check not implemented'}
    
    def _calculate_security_score(self, features: Dict[str, Any]) -> int:
        """Calculate overall security score (0-100)"""
        total_features = 0
        enabled_features = 0
        
        for feature_name, feature_data in features.items():
            if isinstance(feature_data, dict) and 'enabled' in feature_data:
                total_features += 1
                if feature_data['enabled']:
                    enabled_features += 1
        
        if total_features == 0:
            return 0
        
        return int((enabled_features / total_features) * 100)
    
    def _generate_security_recommendations(self, features: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on missing security features"""
        recommendations = []
        
        for feature_name, feature_data in features.items():
            if isinstance(feature_data, dict) and not feature_data.get('enabled', False):
                if feature_name == 'stack_canary':
                    recommendations.append("Enable stack canaries to protect against buffer overflows")
                elif feature_name == 'nx_bit':
                    recommendations.append("Enable NX bit to prevent code execution on the stack")
                elif feature_name == 'aslr':
                    recommendations.append("Enable ASLR to randomize memory layout")
                elif feature_name == 'pie':
                    recommendations.append("Compile as Position Independent Executable (PIE)")
                elif feature_name == 'relro':
                    recommendations.append("Enable RELRO to protect GOT/PLT")
                elif feature_name == 'dep':
                    recommendations.append("Enable DEP (Data Execution Prevention)")
                elif feature_name == 'cfg':
                    recommendations.append("Enable Control Flow Guard (CFG)")
        
        return recommendations[:8]  # Limit to top 8 recommendations
