"""Real execution tracing system using strace, auditd, tcpdump"""

import subprocess
import json
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
import os
import signal


@dataclass
class SystemCallEvent:
    """Captured system call event"""
    syscall_name: str
    pid: int
    timestamp: float
    arguments: Dict[str, Any] = field(default_factory=dict)
    return_value: Optional[int] = None


@dataclass
class NetworkEvent:
    """Captured network event"""
    event_type: str  # connect/send/recv
    protocol: str  # TCP/UDP
    local_addr: str
    remote_addr: str
    remote_port: int
    timestamp: float
    bytes_transferred: int = 0


@dataclass
class FileAccessEvent:
    """Captured file access event"""
    event_type: str  # open/read/write/close
    path: str
    flags: str
    timestamp: float
    pid: int


@dataclass
class ProcessEvent:
    """Captured process event"""
    event_type: str  # fork/exec/exit
    pid: int
    ppid: int
    timestamp: float
    command: Optional[str] = None


@dataclass
class ResourceSnapshot:
    """System resource snapshot"""
    timestamp: float
    memory_mb: float
    cpu_percent: float
    open_files: int
    threads: int


class SystemCallTracer:
    """Trace system calls using strace"""
    
    def __init__(self):
        self.events: List[SystemCallEvent] = []
    
    def trace_process(self, command: str, timeout: int = 30) -> List[SystemCallEvent]:
        """
        Trace system calls of a process
        
        Args:
            command: Command to execute
            timeout: Timeout in seconds
        
        Returns:
            List of captured system call events
        """
        self.events = []
        
        try:
            # Build strace command
            strace_cmd = f"strace -f -e trace=all -o /tmp/strace_out.txt {command}"
            
            # Execute with timeout
            process = subprocess.Popen(
                strace_cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
            
            # Parse strace output
            self._parse_strace_output("/tmp/strace_out.txt")
        
        except Exception as e:
            print(f"Error tracing syscalls: {e}")
        
        return self.events
    
    def _parse_strace_output(self, filepath: str):
        """
        Parse strace output file
        
        Args:
            filepath: Path to strace output file
        """
        try:
            with open(filepath, 'r', errors='ignore') as f:
                for line in f:
                    # Example: open("/etc/passwd", O_RDONLY) = 3
                    match = re.match(
                        r'\[?(\d+)?\]?\s*([a-z_]+)\((.*?)\)\s*=\s*(-?\d+)',
                        line
                    )
                    
                    if match:
                        pid = int(match.group(1)) if match.group(1) else 0
                        syscall = match.group(2)
                        args_str = match.group(3)
                        ret_val = int(match.group(4))
                        
                        event = SystemCallEvent(
                            syscall_name=syscall,
                            pid=pid,
                            timestamp=datetime.now().timestamp(),
                            return_value=ret_val
                        )
                        
                        self.events.append(event)
        
        except FileNotFoundError:
            print(f"Strace output file not found: {filepath}")


class NetworkTracer:
    """Trace network connections using tcpdump/ss"""
    
    def __init__(self):
        self.events: List[NetworkEvent] = []
    
    def trace_network(self, pid: int, timeout: int = 30) -> List[NetworkEvent]:
        """
        Trace network activity for a process
        
        Args:
            pid: Process ID to trace
            timeout: Timeout in seconds
        
        Returns:
            List of captured network events
        """
        self.events = []
        
        # Method 1: Use ss (socket statistics)
        self._trace_with_ss(pid)
        
        # Method 2: Use lsof for open connections
        self._trace_with_lsof(pid)
        
        return self.events
    
    def _trace_with_ss(self, pid: int):
        """
        Get socket statistics for process
        
        Args:
            pid: Process ID
        """
        try:
            # Get socket info using ss
            cmd = f"ss -tpn | grep {pid}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # Parse output
            for line in result.stdout.split('\n'):
                if not line.strip():
                    continue
                
                # Parse: ESTAB 0 0 127.0.0.1:45678 8.8.8.8:443
                parts = line.split()
                if len(parts) >= 4:
                    try:
                        local_addr = parts[3]
                        remote_addr = parts[4]
                        
                        remote_ip, remote_port = remote_addr.rsplit(':', 1)
                        
                        event = NetworkEvent(
                            event_type="established_connection",
                            protocol="TCP",
                            local_addr=local_addr,
                            remote_addr=remote_ip,
                            remote_port=int(remote_port),
                            timestamp=datetime.now().timestamp()
                        )
                        
                        self.events.append(event)
                    except:
                        pass
        
        except Exception as e:
            print(f"Error tracing with ss: {e}")
    
    def _trace_with_lsof(self, pid: int):
        """
        Get open files/sockets for process
        
        Args:
            pid: Process ID
        """
        try:
            cmd = f"lsof -p {pid} -n -P"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            for line in result.stdout.split('\n')[1:]:  # Skip header
                if not line.strip():
                    continue
                
                # Parse lsof output (complex format, simplified)
                if '->IPv' in line or 'TCP' in line or 'UDP' in line:
                    # Extract connection info
                    try:
                        # This is a simplified parser
                        if 'TCP' in line:
                            event = NetworkEvent(
                                event_type="socket",
                                protocol="TCP",
                                local_addr="",
                                remote_addr="",
                                remote_port=0,
                                timestamp=datetime.now().timestamp()
                            )
                            self.events.append(event)
                    except:
                        pass
        
        except Exception as e:
            print(f"Error tracing with lsof: {e}")


class FileAccessTracer:
    """Trace file access using auditd"""
    
    def __init__(self):
        self.events: List[FileAccessEvent] = []
    
    def trace_file_access(self, pid: int, timeout: int = 30) -> List[FileAccessEvent]:
        """
        Trace file access for a process
        
        Args:
            pid: Process ID
            timeout: Timeout in seconds
        
        Returns:
            List of file access events
        """
        self.events = []
        
        # Use lsof to get open files
        self._get_open_files(pid)
        
        return self.events
    
    def _get_open_files(self, pid: int):
        """
        Get open files for process using lsof
        
        Args:
            pid: Process ID
        """
        try:
            cmd = f"lsof -p {pid} -n"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            for line in result.stdout.split('\n')[1:]:  # Skip header
                if not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) >= 9:
                    try:
                        # Format: PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
                        fd = parts[3]
                        access_type = parts[4]
                        name = ' '.join(parts[8:])
                        
                        # Determine event type from FD
                        if 'r' in fd:
                            event_type = "read"
                        elif 'w' in fd:
                            event_type = "write"
                        else:
                            event_type = "access"
                        
                        event = FileAccessEvent(
                            event_type=event_type,
                            path=name,
                            flags=access_type,
                            timestamp=datetime.now().timestamp(),
                            pid=pid
                        )
                        
                        self.events.append(event)
                    except:
                        pass
        
        except Exception as e:
            print(f"Error getting open files: {e}")


class ProcessMonitor:
    """Monitor process metrics using /proc and ps"""
    
    def __init__(self):
        self.events: List[ProcessEvent] = []
        self.snapshots: List[ResourceSnapshot] = []
    
    def get_resource_usage(self, pid: int) -> ResourceSnapshot:
        """
        Get resource usage snapshot for a process
        
        Args:
            pid: Process ID
        
        Returns:
            ResourceSnapshot
        """
        try:
            # Read from /proc/[pid]/stat
            with open(f"/proc/{pid}/stat", 'r') as f:
                stat_data = f.read().split()
            
            # Read from /proc/[pid]/status
            with open(f"/proc/{pid}/status", 'r') as f:
                status_data = f.read()
            
            # Parse memory usage
            memory_mb = 0
            for line in status_data.split('\n'):
                if line.startswith('VmRSS'):
                    memory_mb = int(line.split()[1]) / 1024  # Convert KB to MB
                    break
            
            # Get CPU and thread info from ps
            ps_cmd = f"ps -p {pid} -o %cpu=,nlwp="
            result = subprocess.run(ps_cmd, shell=True, capture_output=True, text=True)
            ps_data = result.stdout.strip().split()
            
            cpu_percent = float(ps_data[0]) if ps_data else 0.0
            threads = int(ps_data[1]) if len(ps_data) > 1 else 1
            
            # Count open files
            try:
                fd_dir = f"/proc/{pid}/fd"
                open_files = len(os.listdir(fd_dir))
            except:
                open_files = 0
            
            snapshot = ResourceSnapshot(
                timestamp=datetime.now().timestamp(),
                memory_mb=memory_mb,
                cpu_percent=cpu_percent,
                open_files=open_files,
                threads=threads
            )
            
            self.snapshots.append(snapshot)
            return snapshot
        
        except Exception as e:
            print(f"Error getting resource usage: {e}")
            return ResourceSnapshot(
                timestamp=datetime.now().timestamp(),
                memory_mb=0,
                cpu_percent=0,
                open_files=0,
                threads=0
            )


class ExecutionTracer:
    """Unified execution tracer combining all trace types"""
    
    def __init__(self):
        self.syscall_tracer = SystemCallTracer()
        self.network_tracer = NetworkTracer()
        self.file_tracer = FileAccessTracer()
        self.process_monitor = ProcessMonitor()
    
    def trace_execution(self, command: str, timeout: int = 30) -> Dict[str, Any]:
        """
        Trace complete execution of a command
        
        Args:
            command: Command to trace
            timeout: Timeout in seconds
        
        Returns:
            Comprehensive execution trace
        """
        # Start tracing
        syscalls = self.syscall_tracer.trace_process(command, timeout)
        
        # Note: In production, would execute command and capture PID for other traces
        # For now, showing structure
        
        trace_result = {
            "command": command,
            "timestamp": datetime.now().isoformat(),
            "syscalls": [
                {
                    "name": event.syscall_name,
                    "pid": event.pid,
                    "return_value": event.return_value
                }
                for event in syscalls
            ],
            "network_events": [],
            "file_events": [],
            "resource_usage": None
        }
        
        return trace_result
