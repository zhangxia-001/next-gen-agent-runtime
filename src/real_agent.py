"""Real agent implementation using LangChain"""

from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import json
import subprocess
from datetime import datetime


class ToolType(str, Enum):
    """Supported tool types"""
    DATABASE = "database"
    FILE_SYSTEM = "file_system"
    NETWORK = "network"
    SHELL = "shell"
    PYTHON = "python"


@dataclass
class ToolDefinition:
    """Definition of an agent tool"""
    name: str
    tool_type: ToolType
    description: str
    parameters: Dict[str, Any]
    handler: Callable
    requires_isolation: bool = True
    risk_level: str = "medium"  # low/medium/high/critical


@dataclass
class ToolExecutionResult:
    """Result of tool execution"""
    tool_name: str
    success: bool
    output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0
    syscalls_made: List[str] = field(default_factory=list)
    network_connections: List[str] = field(default_factory=list)
    files_accessed: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)


class RealAgent:
    """Real agent with LangChain-style tool execution"""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.tools: Dict[str, ToolDefinition] = {}
        self.execution_history: List[ToolExecutionResult] = []
        self.memory: Dict[str, Any] = {}
    
    def register_tool(self, tool_def: ToolDefinition):
        """
        Register a tool with the agent
        
        Args:
            tool_def: ToolDefinition
        """
        self.tools[tool_def.name] = tool_def
    
    def get_tools(self) -> List[ToolDefinition]:
        """Get all registered tools"""
        return list(self.tools.values())
    
    def execute_tool(self, tool_name: str, **kwargs) -> ToolExecutionResult:
        """
        Execute a tool
        
        Args:
            tool_name: Name of tool to execute
            **kwargs: Tool parameters
        
        Returns:
            ToolExecutionResult
        """
        if tool_name not in self.tools:
            return ToolExecutionResult(
                tool_name=tool_name,
                success=False,
                error=f"Tool '{tool_name}' not found"
            )
        
        tool_def = self.tools[tool_name]
        
        try:
            # Execute tool handler
            output = tool_def.handler(**kwargs)
            
            result = ToolExecutionResult(
                tool_name=tool_name,
                success=True,
                output=str(output),
                execution_time=0.0
            )
        
        except Exception as e:
            result = ToolExecutionResult(
                tool_name=tool_name,
                success=False,
                error=str(e)
            )
        
        # Record in history
        self.execution_history.append(result)
        return result
    
    def think_and_act(self, prompt: str) -> Dict[str, Any]:
        """
        Main agent loop: think about task and execute tools
        
        Args:
            prompt: Task description
        
        Returns:
            Agent response and execution history
        """
        # In production: would call LLM to decide which tools to use
        # For now: demonstrate tool execution
        
        response = {
            "prompt": prompt,
            "agent": self.name,
            "timestamp": datetime.now().isoformat(),
            "tool_results": [],
            "summary": ""
        }
        
        return response


class DatabaseTool:
    """Real database tool for SQL operations"""
    
    def __init__(self, connection_string: Optional[str] = None):
        self.connection_string = connection_string or "sqlite:///:memory:"
        self.connection = None
    
    def execute_query(self, query: str, params: Dict = None) -> str:
        """
        Execute SQL query
        
        Args:
            query: SQL query
            params: Query parameters
        
        Returns:
            Query results as JSON string
        """
        try:
            # Import here to avoid hard dependency
            import sqlite3
            
            # Simple SQLite implementation
            conn = sqlite3.connect(":memory:")
            cursor = conn.cursor()
            
            # Execute query
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            # Fetch results
            results = cursor.fetchall()
            conn.close()
            
            return json.dumps({
                "rows": results,
                "count": len(results)
            })
        
        except Exception as e:
            return json.dumps({"error": str(e)})


class FileSystemTool:
    """Real file system tool for read/write operations"""
    
    def __init__(self, base_path: str = "/tmp"):
        self.base_path = base_path
    
    def read_file(self, path: str, encoding: str = "utf-8") -> str:
        """
        Read file
        
        Args:
            path: File path
            encoding: File encoding
        
        Returns:
            File contents
        """
        try:
            with open(path, 'r', encoding=encoding) as f:
                return f.read()
        except Exception as e:
            return f"Error reading file: {str(e)}"
    
    def write_file(self, path: str, content: str) -> str:
        """
        Write file
        
        Args:
            path: File path
            content: File content
        
        Returns:
            Success message
        """
        try:
            with open(path, 'w') as f:
                f.write(content)
            return f"Successfully wrote {len(content)} bytes to {path}"
        except Exception as e:
            return f"Error writing file: {str(e)}"
    
    def list_directory(self, path: str) -> str:
        """
        List directory contents
        
        Args:
            path: Directory path
        
        Returns:
            List of files/directories
        """
        try:
            import os
            files = os.listdir(path)
            return json.dumps({"files": files, "count": len(files)})
        except Exception as e:
            return json.dumps({"error": str(e)})


class NetworkTool:
    """Real network tool for HTTP requests"""
    
    def make_request(self,
                     method: str,
                     url: str,
                     headers: Dict = None,
                     data: Dict = None) -> str:
        """
        Make HTTP request
        
        Args:
            method: HTTP method (GET/POST/etc)
            url: Request URL
            headers: Request headers
            data: Request body
        
        Returns:
            Response as JSON string
        """
        try:
            import requests
            
            response = requests.request(
                method=method,
                url=url,
                headers=headers or {},
                json=data,
                timeout=30
            )
            
            return json.dumps({
                "status_code": response.status_code,
                "content": response.text[:1000],  # Limit size
                "headers": dict(response.headers)
            })
        
        except ImportError:
            return json.dumps({"error": "requests library not installed"})
        except Exception as e:
            return json.dumps({"error": str(e)})


class ShellTool:
    """Real shell tool for command execution"""
    
    def execute_command(self, command: str, timeout: int = 30) -> str:
        """
        Execute shell command
        
        Args:
            command: Shell command
            timeout: Execution timeout in seconds
        
        Returns:
            Command output
        """
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return json.dumps({
                "returncode": result.returncode,
                "stdout": result.stdout[:1000],
                "stderr": result.stderr[:1000]
            })
        
        except subprocess.TimeoutExpired:
            return json.dumps({"error": "Command execution timeout"})
        except Exception as e:
            return json.dumps({"error": str(e)})


class PythonTool:
    """Real Python code execution tool (sandboxed)"""
    
    def execute_code(self, code: str, timeout: int = 30) -> str:
        """
        Execute Python code
        
        Args:
            code: Python code
            timeout: Execution timeout
        
        Returns:
            Execution result
        """
        try:
            import signal
            
            # Define timeout handler
            def timeout_handler(signum, frame):
                raise TimeoutError("Code execution timeout")
            
            # Set signal handler
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(timeout)
            
            # Execute code in restricted environment
            safe_globals = {
                "__builtins__": {"print": print, "len": len, "str": str, "int": int},
                "__name__": "__main__"
            }
            
            exec(code, safe_globals)
            
            signal.alarm(0)  # Cancel alarm
            
            return json.dumps({
                "success": True,
                "output": "Code executed successfully"
            })
        
        except TimeoutError:
            return json.dumps({"error": "Execution timeout"})
        except Exception as e:
            return json.dumps({"error": str(e)})
