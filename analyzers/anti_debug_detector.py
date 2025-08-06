import re
from typing import Dict, List, Any
import subprocess
import tempfile

class AntiDebugDetector:
    def __init__(self):
        # Common anti-debug techniques and their signatures
        self.antidebug_techniques = {
            'ptrace': {
                'description': 'Uses ptrace to detect debuggers',
                'signatures': ['ptrace', 'PTRACE_TRACEME', 'PT_DENY_ATTACH'],
                'strings': ['ptrace', 'PTRACE_TRACEME'],
                'severity': 'high'
            },
            'timing_checks': {
                'description': 'Uses timing to detect debugging',
                'signatures': ['rdtsc', 'QueryPerformanceCounter', 'gettimeofday', 'clock_gettime'],
                'strings': ['rdtsc', 'QueryPerformanceCounter'],
                'severity': 'medium'
            },
            'debugger_detection': {
                'description': 'Directly checks for debugger presence',
                'signatures': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess'],
                'strings': ['IsDebuggerPresent', 'debugger', 'ollydbg', 'x64dbg', 'gdb'],
                'severity': 'high'
            },
            'process_hollowing': {
                'description': 'Process injection/hollowing techniques',
                'signatures': ['CreateProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'SetThreadContext'],
                'strings': ['CreateProcess', 'VirtualAlloc', 'WriteProcessMemory'],
                'severity': 'critical'
            },
            'exception_handling': {
                'description': 'Uses exception handling to detect debugging',
                'signatures': ['SetUnhandledExceptionFilter', 'AddVectoredExceptionHandler'],
                'strings': ['UnhandledException', 'VectoredException'],
                'severity': 'medium'
            },
            'vm_detection': {
                'description': 'Virtual machine and sandbox detection',
                'signatures': ['cpuid', 'VMware', 'VirtualBox', 'QEMU', 'Xen'],
                'strings': ['vmware', 'virtualbox', 'qemu', 'sandbox', 'wine'],
                'severity': 'high'
            },
            'thread_manipulation': {
                'description': 'Thread manipulation for anti-debug',
                'signatures': ['CreateThread', 'SuspendThread', 'ResumeThread', 'TerminateThread'],
                'strings': ['CreateThread', 'SuspendThread'],
                'severity': 'medium'
            },
            'memory_protection': {
                'description': 'Memory protection and integrity checks',
                'signatures': ['VirtualProtect', 'mprotect', 'VirtualQuery'],
                'strings': ['VirtualProtect', 'mprotect'],
                'severity': 'medium'
            },
            'api_hooking': {
                'description': 'API hooking and patching detection',
                'signatures': ['SetWindowsHookEx', 'GetProcAddress', 'LoadLibrary'],
                'strings': ['SetWindowsHookEx', 'GetProcAddress'],
                'severity': 'high'
            },
            'file_system_checks': {
                'description': 'File system based detection',
                'signatures': ['FindFirstFile', 'GetFileAttributes', 'stat', 'access'],
                'strings': ['FindFirstFile', '/proc/', '/sys/'],
                'severity': 'low'
            }
        }
        
        # Debugger-specific strings
        self.debugger_strings = [
            'ollydbg', 'x64dbg', 'x32dbg', 'windbg', 'gdb', 'lldb',
            'ida', 'radare2', 'r2', 'immunity', 'cheat engine',
            'process monitor', 'api monitor', 'detours', 'minhook'
        ]
        
        # Anti-analysis techniques
        self.antialysis_techniques = {
            'packing': ['upx', 'aspack', 'pecompact', 'themida', 'vmprotect'],
            'obfuscation': ['obfuscat', 'confuser', 'dotfuscat', 'babel'],
            'encryption': ['encrypt', 'decrypt', 'cipher', 'aes', 'rc4', 'xor']
        }
    
    def detect_antidebug_techniques(self, file_path: str, strings: List[str]) -> Dict[str, Any]:
        """Main anti-debug detection function"""
        try:
            results = {
                'techniques': self._detect_techniques(strings),
                'debugger_checks': self._detect_debugger_checks(strings),
                'vm_detection': self._detect_vm_checks(strings),
                'timing_attacks': self._detect_timing_attacks(strings),
                'api_obfuscation': self._detect_api_obfuscation(strings),
                'packing_indicators': self._detect_packing(strings),
                'severity_assessment': {},
                'evasion_score': 0,
                'recommendations': []
            }
            
            # Calculate severity and scores
            results['severity_assessment'] = self._assess_severity(results)
            results['evasion_score'] = self._calculate_evasion_score(results)
            results['recommendations'] = self._generate_recommendations(results)
            
            return results
            
        except Exception as e:
            return {'error': f"Anti-debug analysis failed: {str(e)}"}
    
    def _detect_techniques(self, strings: List[str]) -> List[Dict[str, Any]]:
        """Detect anti-debug techniques based on string analysis"""
        detected_techniques = []
        
        # Convert strings to lowercase for case-insensitive matching
        lower_strings = [s.lower() for s in strings]
        combined_strings = ' '.join(lower_strings)
        
        for technique_name, technique_info in self.antidebug_techniques.items():
            matches = []
            
            # Check for signature strings
            for signature in technique_info['signatures']:
                for string in strings:
                    if signature.lower() in string.lower():
                        matches.append(string)
                        break
            
            # Check for technique-specific strings
            for search_string in technique_info['strings']:
                if search_string.lower() in combined_strings:
                    matches.append(search_string)
            
            if matches:
                detected_techniques.append({
                    'name': technique_name,
                    'description': technique_info['description'],
                    'severity': technique_info['severity'],
                    'matches': list(set(matches)),  # Remove duplicates
                    'confidence': self._calculate_confidence(matches, technique_info)
                })
        
        return detected_techniques
    
    def _detect_debugger_checks(self, strings: List[str]) -> List[str]:
        """Detect specific debugger name checks"""
        found_debuggers = []
        combined_strings = ' '.join(strings).lower()
        
        for debugger in self.debugger_strings:
            if debugger in combined_strings:
                found_debuggers.append(debugger)
        
        return found_debuggers
    
    def _detect_vm_checks(self, strings: List[str]) -> List[Dict[str, str]]:
        """Detect virtual machine and sandbox detection"""
        vm_indicators = [
            {'name': 'VMware', 'strings': ['vmware', 'vmx', 'vmmouse', 'vmhgfs']},
            {'name': 'VirtualBox', 'strings': ['vbox', 'virtualbox', 'vboxservice']},
            {'name': 'QEMU', 'strings': ['qemu', 'qemu-ga']},
            {'name': 'Xen', 'strings': ['xen', 'xenbus', 'xensource']},
            {'name': 'Hyper-V', 'strings': ['hyperv', 'vmbus', 'hypercall']},
            {'name': 'Wine', 'strings': ['wine', 'wineserver', 'ntdll.dll.so']},
            {'name': 'Sandbox', 'strings': ['sandbox', 'malware', 'virus', 'sample']}
        ]
        
        detected_vms = []
        combined_strings = ' '.join(strings).lower()
        
        for vm in vm_indicators:
            matches = [s for s in vm['strings'] if s in combined_strings]
            if matches:
                detected_vms.append({
                    'vm_name': vm['name'],
                    'indicators': matches
                })
        
        return detected_vms
    
    def _detect_timing_attacks(self, strings: List[str]) -> List[str]:
        """Detect timing-based anti-debug techniques"""
        timing_functions = [
            'rdtsc', 'rdtscp', 'QueryPerformanceCounter', 'GetTickCount',
            'timeGetTime', 'gettimeofday', 'clock_gettime', 'clock',
            'time', 'ftime', 'GetSystemTime'
        ]
        
        found_timing = []
        combined_strings = ' '.join(strings).lower()
        
        for func in timing_functions:
            if func.lower() in combined_strings:
                found_timing.append(func)
        
        return found_timing
    
    def _detect_api_obfuscation(self, strings: List[str]) -> Dict[str, List[str]]:
        """Detect API obfuscation and dynamic loading"""
        obfuscation_indicators = {
            'dynamic_loading': ['LoadLibrary', 'GetProcAddress', 'dlopen', 'dlsym'],
            'string_obfuscation': ['decode', 'decrypt', 'deobfuscate', 'unpack'],
            'api_hashing': ['hash', 'crc32', 'djb2', 'fnv'],
            'indirect_calls': ['call', 'jmp', 'invoke', 'dispatch']
        }
        
        detected_obfuscation = {}
        combined_strings = ' '.join(strings).lower()
        
        for category, indicators in obfuscation_indicators.items():
            matches = [ind for ind in indicators if ind.lower() in combined_strings]
            if matches:
                detected_obfuscation[category] = matches
        
        return detected_obfuscation
    
    def _detect_packing(self, strings: List[str]) -> Dict[str, List[str]]:
        """Detect packing and anti-analysis techniques"""
        detected_techniques = {}
        combined_strings = ' '.join(strings).lower()
        
        for category, indicators in self.antialysis_techniques.items():
            matches = [ind for ind in indicators if ind.lower() in combined_strings]
            if matches:
                detected_techniques[category] = matches
        
        return detected_techniques
    
    def _calculate_confidence(self, matches: List[str], technique_info: Dict[str, Any]) -> str:
        """Calculate confidence level for detected technique"""
        match_count = len(matches)
        signature_count = len(technique_info['signatures'])
        
        if match_count >= signature_count * 0.8:
            return 'high'
        elif match_count >= signature_count * 0.5:
            return 'medium'
        else:
            return 'low'
    
    def _assess_severity(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall severity of anti-debug techniques"""
        techniques = results.get('techniques', [])
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for technique in techniques:
            severity = technique.get('severity', 'low')
            severity_counts[severity] += 1
        
        # Determine overall threat level
        if severity_counts['critical'] > 0:
            threat_level = 'CRITICAL'
        elif severity_counts['high'] > 2:
            threat_level = 'HIGH'
        elif severity_counts['high'] > 0 or severity_counts['medium'] > 3:
            threat_level = 'MEDIUM'
        elif severity_counts['medium'] > 0 or severity_counts['low'] > 5:
            threat_level = 'LOW'
        else:
            threat_level = 'MINIMAL'
        
        return {
            'threat_level': threat_level,
            'severity_breakdown': severity_counts,
            'total_techniques': len(techniques)
        }
    
    def _calculate_evasion_score(self, results: Dict[str, Any]) -> int:
        """Calculate evasion score (0-100)"""
        score = 0
        
        # Score based on techniques
        techniques = results.get('techniques', [])
        for technique in techniques:
            severity = technique.get('severity', 'low')
            confidence = technique.get('confidence', 'low')
            
            base_score = {'critical': 25, 'high': 15, 'medium': 8, 'low': 3}[severity]
            confidence_multiplier = {'high': 1.0, 'medium': 0.7, 'low': 0.4}[confidence]
            
            score += int(base_score * confidence_multiplier)
        
        # Additional scoring
        if results.get('debugger_checks'):
            score += len(results['debugger_checks']) * 5
        
        if results.get('vm_detection'):
            score += len(results['vm_detection']) * 8
        
        if results.get('timing_attacks'):
            score += len(results['timing_attacks']) * 3
        
        if results.get('api_obfuscation'):
            score += sum(len(v) for v in results['api_obfuscation'].values()) * 2
        
        if results.get('packing_indicators'):
            score += sum(len(v) for v in results['packing_indicators'].values()) * 10
        
        return min(score, 100)  # Cap at 100
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate recommendations for analyzing protected binaries"""
        recommendations = []
        techniques = results.get('techniques', [])
        threat_level = results.get('severity_assessment', {}).get('threat_level', 'LOW')
        
        # General recommendations based on threat level
        if threat_level in ['CRITICAL', 'HIGH']:
            recommendations.append("🚨 This binary has strong anti-debug protection")
            recommendations.append("Consider using advanced analysis techniques or specialized tools")
            recommendations.append("Static analysis may be more effective than dynamic analysis")
        
        # Specific recommendations based on detected techniques
        technique_names = [t.get('name', '') for t in techniques]
        
        if 'ptrace' in technique_names:
            recommendations.append("Use GDB with anti-ptrace bypass techniques")
            recommendations.append("Consider using LD_PRELOAD to hook ptrace calls")
        
        if 'timing_checks' in technique_names:
            recommendations.append("Use debuggers with timing attack mitigation")
            recommendations.append("Consider modifying timing-related system calls")
        
        if 'vm_detection' in technique_names:
            recommendations.append("Use bare-metal analysis environment")
            recommendations.append("Patch VM detection routines before analysis")
        
        if 'debugger_detection' in technique_names:
            recommendations.append("Use stealthy debuggers or patch detection routines")
            recommendations.append("Consider using hardware breakpoints instead of software ones")
        
        if results.get('packing_indicators'):
            recommendations.append("Unpack the binary before detailed analysis")
            recommendations.append("Use automated unpacking tools when possible")
        
        # General analysis recommendations
        recommendations.extend([
            "Use multiple analysis approaches (static, dynamic, hybrid)",
            "Consider using emulation-based analysis tools",
            "Document all anti-analysis techniques for reporting",
            "Use specialized anti-anti-debug tools and plugins"
        ])
        
        return recommendations[:10]  # Limit to top 10 recommendations
    
    def get_technique_details(self, technique_name: str) -> Dict[str, Any]:
        """Get detailed information about a specific technique"""
        return self.antidebug_techniques.get(technique_name, {
            'description': 'Unknown anti-debug technique',
            'severity': 'unknown',
            'signatures': [],
            'strings': []
        })
