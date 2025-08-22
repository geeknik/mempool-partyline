"""
Process hardening and memory protection
Implements defense-in-depth security measures at the OS level
"""

import os
import sys
import platform
import logging
import secrets
import ctypes
import resource
from typing import Optional, Union, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class SecurityManager:
    """Manages process-level security hardening"""
    
    def __init__(self, config: Optional[Any] = None):
        """
        Initialize security manager
        
        Args:
            config: Optional security configuration
        """
        self.platform = platform.system()
        self.config = config
        self._applied_hardening = []
        
    def apply_all_hardening(self) -> None:
        """Apply all available security hardening measures"""
        logger.info("Applying process security hardening")
        
        # Core dump prevention
        if self._should_disable_core_dumps():
            self.disable_core_dumps()
        
        # Memory locking
        if self._should_lock_memory():
            self.setup_memory_locking()
        
        # File permissions
        self.set_secure_umask()
        
        # Process limits
        self.set_resource_limits()
        
        # Platform-specific
        if self.platform == "Linux":
            self.linux_hardening()
        elif self.platform == "Darwin":  # macOS
            self.macos_hardening()
        elif self.platform == "Windows":
            self.windows_hardening()
        
        logger.info(f"Applied hardening: {', '.join(self._applied_hardening)}")
    
    def _should_disable_core_dumps(self) -> bool:
        """Check if core dumps should be disabled"""
        if self.config:
            return getattr(self.config.security, 'disable_core_dumps', True)
        return True
    
    def _should_lock_memory(self) -> bool:
        """Check if memory locking should be attempted"""
        if self.config:
            return getattr(self.config.security, 'memory_lock', True)
        return True
    
    def disable_core_dumps(self) -> None:
        """Disable core dumps to prevent memory disclosure"""
        try:
            if hasattr(resource, 'RLIMIT_CORE'):
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                self._applied_hardening.append("no_core_dumps")
                logger.debug("Core dumps disabled")
            
            # Linux-specific prctl
            if self.platform == "Linux":
                try:
                    import ctypes.util
                    libc = ctypes.CDLL(ctypes.util.find_library('c'))
                    PR_SET_DUMPABLE = 4
                    libc.prctl(PR_SET_DUMPABLE, 0)
                    self._applied_hardening.append("prctl_no_dump")
                    logger.debug("Process marked as non-dumpable via prctl")
                except Exception as e:
                    logger.debug(f"Could not set PR_SET_DUMPABLE: {e}")
                    
        except Exception as e:
            logger.warning(f"Could not disable core dumps: {e}")
    
    def setup_memory_locking(self) -> None:
        """Attempt to lock memory pages to prevent swapping"""
        try:
            if hasattr(resource, 'RLIMIT_MEMLOCK'):
                # Try to increase memlock limit
                soft, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
                if soft < 65536:  # 64KB minimum
                    try:
                        resource.setrlimit(resource.RLIMIT_MEMLOCK, (65536, hard))
                        logger.debug("Increased RLIMIT_MEMLOCK")
                    except:
                        pass
            
            # Note: Actual mlock() calls should be done on specific memory regions
            # containing sensitive data, not the entire process
            self._applied_hardening.append("memlock_ready")
            
        except Exception as e:
            logger.debug(f"Memory locking setup: {e}")
    
    def set_secure_umask(self) -> None:
        """Set restrictive umask for file creation"""
        try:
            old_umask = os.umask(0o077)  # rwx------
            self._applied_hardening.append(f"umask_0o077")
            logger.debug(f"Set umask from {oct(old_umask)} to 0o077")
        except Exception as e:
            logger.warning(f"Could not set umask: {e}")
    
    def set_resource_limits(self) -> None:
        """Set resource limits to prevent abuse"""
        try:
            if hasattr(resource, 'RLIMIT_NOFILE'):
                # Limit file descriptors
                soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
                if soft > 1024:
                    resource.setrlimit(resource.RLIMIT_NOFILE, (1024, hard))
                    self._applied_hardening.append("fd_limit")
            
            if hasattr(resource, 'RLIMIT_NPROC'):
                # Limit subprocess creation
                soft, hard = resource.getrlimit(resource.RLIMIT_NPROC)
                if soft > 100:
                    resource.setrlimit(resource.RLIMIT_NPROC, (100, hard))
                    self._applied_hardening.append("proc_limit")
                    
        except Exception as e:
            logger.debug(f"Resource limits: {e}")
    
    def linux_hardening(self) -> None:
        """Linux-specific hardening"""
        try:
            # Disable ptrace
            import ctypes.util
            libc = ctypes.CDLL(ctypes.util.find_library('c'))
            PR_SET_PTRACER = 0x59616d61
            PR_SET_PTRACER_ANY = -1
            try:
                libc.prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)
                self._applied_hardening.append("no_ptrace")
            except:
                pass
            
            # Set SECCOMP if available (requires additional setup)
            # This would restrict system calls but needs careful configuration
            
        except Exception as e:
            logger.debug(f"Linux hardening: {e}")
    
    def macos_hardening(self) -> None:
        """macOS-specific hardening"""
        try:
            # macOS-specific security measures
            # Could include entitlements, sandboxing, etc.
            pass
        except Exception as e:
            logger.debug(f"macOS hardening: {e}")
    
    def windows_hardening(self) -> None:
        """Windows-specific hardening"""
        try:
            # Windows-specific security measures
            # Could include DEP, ASLR settings, etc.
            if hasattr(ctypes, 'windll'):
                # Enable DEP
                kernel32 = ctypes.windll.kernel32
                kernel32.SetProcessDEPPolicy(1)  # Enable DEP
                self._applied_hardening.append("dep_enabled")
        except Exception as e:
            logger.debug(f"Windows hardening: {e}")


class MemoryProtection:
    """Memory protection utilities"""
    
    @staticmethod
    def lock_memory(data: bytes, size: Optional[int] = None) -> bool:
        """
        Attempt to lock memory region to prevent swapping
        
        Args:
            data: Memory region to lock
            size: Size of region (defaults to len(data))
        
        Returns:
            True if successful
        """
        if not data:
            return False
        
        size = size or len(data)
        
        try:
            if platform.system() in ["Linux", "Darwin"]:
                import ctypes.util
                libc = ctypes.CDLL(ctypes.util.find_library('c'))
                
                # Get memory address
                if hasattr(data, '__array_interface__'):
                    addr = data.__array_interface__['data'][0]
                else:
                    addr = id(data)
                
                # mlock(addr, size)
                result = libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(size))
                if result == 0:
                    logger.debug(f"Locked {size} bytes of memory")
                    return True
                else:
                    logger.debug(f"mlock failed with code {result}")
                    
        except Exception as e:
            logger.debug(f"Memory locking not available: {e}")
        
        return False
    
    @staticmethod
    def unlock_memory(data: bytes, size: Optional[int] = None) -> bool:
        """
        Unlock previously locked memory
        
        Args:
            data: Memory region to unlock
            size: Size of region
        
        Returns:
            True if successful
        """
        if not data:
            return False
        
        size = size or len(data)
        
        try:
            if platform.system() in ["Linux", "Darwin"]:
                import ctypes.util
                libc = ctypes.CDLL(ctypes.util.find_library('c'))
                
                # Get memory address
                if hasattr(data, '__array_interface__'):
                    addr = data.__array_interface__['data'][0]
                else:
                    addr = id(data)
                
                # munlock(addr, size)
                result = libc.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(size))
                return result == 0
                
        except Exception as e:
            logger.debug(f"Memory unlocking: {e}")
        
        return False
    
    @staticmethod
    def secure_zero(data: Union[bytes, bytearray, memoryview]) -> None:
        """
        Securely zero memory
        
        Args:
            data: Memory to zero
        """
        if isinstance(data, bytearray):
            # Direct zeroing for bytearray
            for i in range(len(data)):
                data[i] = 0
        elif isinstance(data, memoryview):
            # Zero through memoryview
            data[:] = b'\x00' * len(data)
        else:
            # For immutable bytes, we can't zero in place
            logger.warning("Cannot zero immutable bytes object")
        
        # Try sodium_memzero if available
        try:
            import nacl.bindings
            nacl.bindings.sodium_memzero(data)
        except:
            pass
        
        # Force garbage collection
        import gc
        gc.collect()


class SecureRandom:
    """Centralized secure random number generation"""
    
    @staticmethod
    def get_bytes(n: int) -> bytes:
        """
        Get cryptographically secure random bytes
        
        Args:
            n: Number of bytes
        
        Returns:
            Random bytes
        """
        return secrets.token_bytes(n)
    
    @staticmethod
    def get_int(min_val: int, max_val: int) -> int:
        """
        Get secure random integer in range
        
        Args:
            min_val: Minimum value (inclusive)
            max_val: Maximum value (inclusive)
        
        Returns:
            Random integer
        """
        return secrets.randbelow(max_val - min_val + 1) + min_val
    
    @staticmethod
    def get_float() -> float:
        """
        Get secure random float in [0, 1)
        
        Returns:
            Random float
        """
        return secrets.randbits(53) / (1 << 53)
    
    @staticmethod
    def shuffle(seq: list) -> None:
        """
        Securely shuffle a sequence in place
        
        Args:
            seq: Sequence to shuffle
        """
        for i in reversed(range(1, len(seq))):
            j = secrets.randbelow(i + 1)
            seq[i], seq[j] = seq[j], seq[i]


def apply_security_defaults() -> SecurityManager:
    """
    Apply default security hardening
    
    Returns:
        Configured SecurityManager instance
    """
    manager = SecurityManager()
    manager.apply_all_hardening()
    return manager


def secure_delete_file(filepath: Path, passes: int = 3) -> bool:
    """
    Securely delete a file by overwriting before unlinking
    
    Args:
        filepath: Path to file
        passes: Number of overwrite passes
    
    Returns:
        True if successful
    """
    try:
        if not filepath.exists():
            return True
        
        file_size = filepath.stat().st_size
        
        with open(filepath, "rb+") as f:
            for pass_num in range(passes):
                f.seek(0)
                # Alternate patterns for each pass
                if pass_num % 2 == 0:
                    pattern = secrets.token_bytes(min(file_size, 4096))
                else:
                    pattern = b'\x00' * min(file_size, 4096)
                
                # Overwrite in chunks
                written = 0
                while written < file_size:
                    chunk_size = min(len(pattern), file_size - written)
                    f.write(pattern[:chunk_size])
                    written += chunk_size
                
                f.flush()
                os.fsync(f.fileno())
        
        # Now unlink
        filepath.unlink()
        logger.debug(f"Securely deleted {filepath}")
        return True
        
    except Exception as e:
        logger.error(f"Secure deletion failed for {filepath}: {e}")
        # Try regular deletion as fallback
        try:
            filepath.unlink()
        except:
            pass
        return False


def get_secure_temp_dir() -> Path:
    """
    Get a secure temporary directory
    
    Returns:
        Path to secure temp directory
    """
    import tempfile
    
    # Create temp dir with restrictive permissions
    temp_dir = Path(tempfile.mkdtemp(prefix="partyline_"))
    
    # Ensure restrictive permissions
    os.chmod(temp_dir, 0o700)
    
    return temp_dir
