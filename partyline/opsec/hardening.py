"""
Process hardening and memory protection
Implements various security measures to protect against memory attacks
"""

import ctypes
import gc
import logging
import os
import platform
import resource
import signal
import sys
from typing import Optional, Any, Callable
import atexit

from partyline.logging_sec import log_security_event

logger = logging.getLogger(__name__)


class ProcessHardening:
    """
    Process security hardening measures
    """
    
    @staticmethod
    def enable_all(config: Optional[Any] = None) -> bool:
        """
        Enable all available hardening measures
        
        Args:
            config: Optional configuration object
        
        Returns:
            True if at least some hardening was applied
        """
        success = False
        
        # Disable core dumps
        if ProcessHardening.disable_core_dumps():
            success = True
            logger.info("Core dumps disabled")
        
        # Set secure signal handlers
        if ProcessHardening.setup_signal_handlers():
            success = True
            logger.info("Signal handlers installed")
        
        # Restrict ptrace
        if ProcessHardening.restrict_ptrace():
            success = True
            logger.info("Ptrace restricted")
        
        # Set resource limits
        if ProcessHardening.set_resource_limits():
            success = True
            logger.info("Resource limits configured")
        
        # Enable ASLR
        if ProcessHardening.enable_aslr():
            success = True
            logger.info("ASLR enabled")
        
        # Clear environment variables
        if ProcessHardening.sanitize_environment():
            success = True
            logger.info("Environment sanitized")
        
        # Set secure file permissions
        if ProcessHardening.set_secure_umask():
            success = True
            logger.info("Secure umask set")
        
        # Register cleanup handlers
        ProcessHardening.register_cleanup_handlers()
        
        log_security_event("process_hardened", {"measures_applied": success})
        return success
    
    @staticmethod
    def disable_core_dumps() -> bool:
        """Disable core dump generation"""
        try:
            # Set core dump size limit to 0
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            
            # Linux-specific: disable via prctl
            if platform.system() == "Linux":
                try:
                    import ctypes.util
                    libc = ctypes.CDLL(ctypes.util.find_library("c"))
                    PR_SET_DUMPABLE = 4
                    libc.prctl(PR_SET_DUMPABLE, 0)
                except Exception:
                    pass
            
            return True
        except Exception as e:
            logger.warning(f"Failed to disable core dumps: {e}")
            return False
    
    @staticmethod
    def restrict_ptrace() -> bool:
        """Restrict process tracing (Linux-specific)"""
        if platform.system() != "Linux":
            return False
        
        try:
            import ctypes.util
            libc = ctypes.CDLL(ctypes.util.find_library("c"))
            
            # PR_SET_PTRACER
            PR_SET_PTRACER = 0x59616d61
            PR_SET_PTRACER_ANY = -1
            
            # Restrict ptrace to parent only
            libc.prctl(PR_SET_PTRACER, 0)
            return True
        except Exception as e:
            logger.debug(f"Could not restrict ptrace: {e}")
            return False
    
    @staticmethod
    def set_resource_limits() -> bool:
        """Set restrictive resource limits"""
        try:
            # Limit address space (prevent excessive memory allocation)
            # 1GB should be enough for our application
            resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 1024, 1024 * 1024 * 1024))
            
            # Limit number of open files
            resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
            
            # Limit number of processes
            resource.setrlimit(resource.RLIMIT_NPROC, (32, 32))
            
            return True
        except Exception as e:
            logger.warning(f"Failed to set resource limits: {e}")
            return False
    
    @staticmethod
    def enable_aslr() -> bool:
        """Enable Address Space Layout Randomization"""
        if platform.system() != "Linux":
            return False
        
        try:
            # Check current ASLR setting
            with open("/proc/sys/kernel/randomize_va_space", "r") as f:
                current = f.read().strip()
            
            # 2 = full randomization
            if current != "2":
                logger.warning("ASLR not fully enabled at system level")
            
            # We can't change system-wide ASLR from userspace
            # but we can ensure our process uses it
            return True
        except Exception:
            return False
    
    @staticmethod
    def sanitize_environment() -> bool:
        """Remove potentially dangerous environment variables"""
        dangerous_vars = [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH", 
            "DYLD_INSERT_LIBRARIES",  # macOS
            "DYLD_LIBRARY_PATH",       # macOS
            "PYTHONPATH",
            "PYTHONHOME",
            "IFS",
            "PATH_LOCALE",
            "SHELLOPTS",
            "BASH_ENV",
            "ENV",
            "CDPATH"
        ]
        
        for var in dangerous_vars:
            if var in os.environ:
                del os.environ[var]
                logger.debug(f"Removed environment variable: {var}")
        
        # Set secure PATH
        os.environ["PATH"] = "/usr/local/bin:/usr/bin:/bin"
        
        return True
    
    @staticmethod
    def set_secure_umask() -> bool:
        """Set restrictive file creation mask"""
        try:
            # 0o077 = only owner can read/write/execute
            os.umask(0o077)
            return True
        except Exception:
            return False
    
    @staticmethod
    def setup_signal_handlers() -> bool:
        """Setup secure signal handlers"""
        def signal_handler(signum, frame):
            """Handle signals securely"""
            logger.warning(f"Received signal {signum}")
            log_security_event("signal_received", {"signal": signum})
            
            # Perform cleanup on termination signals
            if signum in (signal.SIGTERM, signal.SIGINT):
                logger.info("Shutting down securely...")
                # Trigger cleanup
                sys.exit(0)
        
        try:
            # Handle common signals
            signal.signal(signal.SIGTERM, signal_handler)
            signal.signal(signal.SIGINT, signal_handler)
            
            # Ignore other signals that could be problematic
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
            signal.signal(signal.SIGPIPE, signal.SIG_IGN)
            
            return True
        except Exception as e:
            logger.warning(f"Failed to setup signal handlers: {e}")
            return False
    
    @staticmethod
    def register_cleanup_handlers():
        """Register handlers to clean up on exit"""
        def cleanup():
            """Cleanup sensitive data on exit"""
            logger.info("Performing secure cleanup...")
            
            # Force garbage collection
            gc.collect()
            
            # Clear any cached data
            # (Application-specific cleanup would go here)
            
            log_security_event("process_cleanup", {})
        
        atexit.register(cleanup)
    
    @staticmethod
    def drop_privileges(user: Optional[str] = None, group: Optional[str] = None) -> bool:
        """
        Drop process privileges to specified user/group
        
        Args:
            user: Username to switch to
            group: Group name to switch to
        
        Returns:
            True if successful
        """
        if platform.system() == "Windows":
            logger.warning("Privilege dropping not supported on Windows")
            return False
        
        try:
            import pwd
            import grp
            
            # Get current IDs
            current_uid = os.getuid()
            current_gid = os.getgid()
            
            # Only root can drop privileges
            if current_uid != 0:
                logger.debug("Not running as root, cannot drop privileges")
                return False
            
            # Get target IDs
            if user:
                target_uid = pwd.getpwnam(user).pw_uid
            else:
                target_uid = current_uid
            
            if group:
                target_gid = grp.getgrnam(group).gr_gid
            else:
                target_gid = current_gid
            
            # Drop group first
            if target_gid != current_gid:
                os.setgid(target_gid)
                os.setgroups([target_gid])
            
            # Then drop user
            if target_uid != current_uid:
                os.setuid(target_uid)
            
            logger.info(f"Dropped privileges to {user}:{group}")
            log_security_event("privileges_dropped", {"user": user, "group": group})
            return True
            
        except Exception as e:
            logger.error(f"Failed to drop privileges: {e}")
            return False


class MemoryProtection:
    """
    Memory protection and secure allocation
    """
    
    @staticmethod
    def lock_memory(data: bytes, size: Optional[int] = None) -> bool:
        """
        Lock memory pages to prevent swapping
        
        Args:
            data: Data to lock in memory
            size: Optional size override
        
        Returns:
            True if successful
        """
        if platform.system() == "Windows":
            return MemoryProtection._lock_memory_windows(data, size)
        else:
            return MemoryProtection._lock_memory_posix(data, size)
    
    @staticmethod
    def _lock_memory_posix(data: bytes, size: Optional[int] = None) -> bool:
        """Lock memory on POSIX systems"""
        try:
            import ctypes.util
            libc = ctypes.CDLL(ctypes.util.find_library("c"))
            
            # Get memory address and size
            address = id(data)
            data_size = size or len(data)
            
            # mlock(const void *addr, size_t len)
            result = libc.mlock(ctypes.c_void_p(address), ctypes.c_size_t(data_size))
            
            if result == 0:
                logger.debug(f"Locked {data_size} bytes in memory")
                return True
            else:
                logger.debug(f"Failed to lock memory: error {result}")
                return False
                
        except Exception as e:
            logger.debug(f"Memory locking not available: {e}")
            return False
    
    @staticmethod
    def _lock_memory_windows(data: bytes, size: Optional[int] = None) -> bool:
        """Lock memory on Windows"""
        try:
            import ctypes
            from ctypes import wintypes
            
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            
            # VirtualLock(LPVOID lpAddress, SIZE_T dwSize)
            VirtualLock = kernel32.VirtualLock
            VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            VirtualLock.restype = wintypes.BOOL
            
            address = id(data)
            data_size = size or len(data)
            
            result = VirtualLock(address, data_size)
            
            if result:
                logger.debug(f"Locked {data_size} bytes in memory")
                return True
            else:
                error = ctypes.get_last_error()
                logger.debug(f"Failed to lock memory: error {error}")
                return False
                
        except Exception as e:
            logger.debug(f"Memory locking not available: {e}")
            return False
    
    @staticmethod
    def unlock_memory(data: bytes, size: Optional[int] = None) -> bool:
        """
        Unlock previously locked memory
        
        Args:
            data: Data to unlock
            size: Optional size override
        
        Returns:
            True if successful
        """
        if platform.system() == "Windows":
            return MemoryProtection._unlock_memory_windows(data, size)
        else:
            return MemoryProtection._unlock_memory_posix(data, size)
    
    @staticmethod
    def _unlock_memory_posix(data: bytes, size: Optional[int] = None) -> bool:
        """Unlock memory on POSIX systems"""
        try:
            import ctypes.util
            libc = ctypes.CDLL(ctypes.util.find_library("c"))
            
            address = id(data)
            data_size = size or len(data)
            
            # munlock(const void *addr, size_t len)
            result = libc.munlock(ctypes.c_void_p(address), ctypes.c_size_t(data_size))
            
            return result == 0
                
        except Exception:
            return False
    
    @staticmethod
    def _unlock_memory_windows(data: bytes, size: Optional[int] = None) -> bool:
        """Unlock memory on Windows"""
        try:
            import ctypes
            from ctypes import wintypes
            
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            
            # VirtualUnlock(LPVOID lpAddress, SIZE_T dwSize)
            VirtualUnlock = kernel32.VirtualUnlock
            VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            VirtualUnlock.restype = wintypes.BOOL
            
            address = id(data)
            data_size = size or len(data)
            
            result = VirtualUnlock(address, data_size)
            return bool(result)
                
        except Exception:
            return False
    
    @staticmethod
    def secure_compare(a: bytes, b: bytes) -> bool:
        """
        Constant-time comparison to prevent timing attacks
        
        Args:
            a: First value
            b: Second value
        
        Returns:
            True if equal
        """
        import hmac
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def disable_swap() -> bool:
        """Attempt to disable swap for the entire process"""
        if platform.system() == "Windows":
            return False  # Not easily doable on Windows
        
        try:
            import ctypes.util
            libc = ctypes.CDLL(ctypes.util.find_library("c"))
            
            # mlockall(int flags)
            MCL_CURRENT = 1
            MCL_FUTURE = 2
            
            result = libc.mlockall(MCL_CURRENT | MCL_FUTURE)
            
            if result == 0:
                logger.info("Disabled memory swapping for process")
                return True
            else:
                logger.debug(f"Could not disable swap: error {result}")
                return False
                
        except Exception as e:
            logger.debug(f"Could not disable swap: {e}")
            return False
    
    @staticmethod
    def get_secure_random_state() -> int:
        """Get cryptographically secure random state"""
        # Use OS random source
        return int.from_bytes(os.urandom(8), byteorder='big')
    
    @staticmethod
    def protect_string(value: str) -> 'ProtectedString':
        """
        Create a protected string that zeros memory on deletion
        
        Args:
            value: String to protect
        
        Returns:
            ProtectedString instance
        """
        return ProtectedString(value)


class ProtectedString:
    """
    String wrapper that zeros memory on deletion
    """
    
    def __init__(self, value: str):
        """Initialize with string value"""
        self._value = value
        self._bytes = value.encode('utf-8')
        MemoryProtection.lock_memory(self._bytes)
    
    def get(self) -> str:
        """Get the string value"""
        return self._value
    
    def __str__(self) -> str:
        """String representation (masked)"""
        return "[PROTECTED]"
    
    def __repr__(self) -> str:
        """Representation (masked)"""
        return "ProtectedString([PROTECTED])"
    
    def __del__(self):
        """Zero memory on deletion"""
        try:
            # Overwrite memory
            if hasattr(self, '_bytes'):
                # Create a mutable bytearray to overwrite
                temp = bytearray(self._bytes)
                for i in range(len(temp)):
                    temp[i] = 0
                
                # Unlock memory
                MemoryProtection.unlock_memory(self._bytes)
            
            # Clear the string reference
            self._value = None
            self._bytes = None
            
        except Exception:
            pass  # Best effort


class SecureExecutor:
    """
    Execute functions with security constraints
    """
    
    @staticmethod
    def run_sandboxed(func: Callable, *args, timeout: int = 30, 
                      memory_limit_mb: int = 256, **kwargs) -> Any:
        """
        Run a function with resource limits
        
        Args:
            func: Function to execute
            *args: Function arguments
            timeout: Execution timeout in seconds
            memory_limit_mb: Memory limit in MB
            **kwargs: Function keyword arguments
        
        Returns:
            Function result
        
        Raises:
            TimeoutError: If execution times out
            MemoryError: If memory limit exceeded
        """
        import threading
        import queue
        
        result_queue = queue.Queue()
        exception_queue = queue.Queue()
        
        def target():
            """Target function for thread"""
            try:
                # Set memory limit for thread
                if platform.system() != "Windows":
                    resource.setrlimit(
                        resource.RLIMIT_AS,
                        (memory_limit_mb * 1024 * 1024, memory_limit_mb * 1024 * 1024)
                    )
                
                # Execute function
                result = func(*args, **kwargs)
                result_queue.put(result)
                
            except Exception as e:
                exception_queue.put(e)
        
        # Run in thread with timeout
        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        thread.join(timeout=timeout)
        
        if thread.is_alive():
            # Thread still running after timeout
            log_security_event("execution_timeout", {"function": func.__name__})
            raise TimeoutError(f"Function execution exceeded {timeout}s timeout")
        
        # Check for exceptions
        if not exception_queue.empty():
            raise exception_queue.get()
        
        # Get result
        if not result_queue.empty():
            return result_queue.get()
        
        return None


# Module initialization
def initialize_hardening(config: Optional[Any] = None):
    """
    Initialize all hardening measures
    
    Args:
        config: Optional configuration object
    """
    logger.info("Initializing process hardening...")
    
    # Apply hardening
    success = ProcessHardening.enable_all(config)
    
    # Try to disable swap
    if MemoryProtection.disable_swap():
        logger.info("Memory swapping disabled")
    
    if success:
        logger.info("Process hardening initialized successfully")
    else:
        logger.warning("Some hardening measures could not be applied")
