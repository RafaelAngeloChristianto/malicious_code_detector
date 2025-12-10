#!/usr/bin/env python3
"""
PHASE 2: SYNTAX ANALYSIS (Parsing)

This module parses tokenized Python code into an Abstract Syntax Tree (AST).
Uses Python's built-in ast.parse() for robust and complete Python grammar support.
"""

import ast
from typing import Dict, Any


class PythonParser:
    """PHASE 2: Syntax Analyzer - Builds Abstract Syntax Tree from source code"""
    
    def __init__(self, source: str, filename: str = "<unknown>"):
        self.source = source
        self.filename = filename
        self.ast_tree = None
        self.statistics = {}
    
    def parse(self) -> ast.AST:
        """
        Parse source code into AST.
        
        This uses Python's built-in parser (equivalent to using yacc/bison
        in traditional compiler construction). The grammar has 331 production
        rules covering all Python 3.x syntax.
        
        Returns:
            AST tree representing the parsed program structure
        
        Raises:
            SyntaxError: If the source code has syntax errors
        """
        try:
            self.ast_tree = ast.parse(self.source, filename=self.filename)
            self._gather_statistics()
            return self.ast_tree
            
        except SyntaxError as e:
            self.statistics = {
                "error": str(e),
                "line": e.lineno,
                "offset": e.offset,
                "text": e.text
            }
            raise
    
    def _gather_statistics(self):
        """Collect statistics about the AST structure"""
        if self.ast_tree is None:
            return
        
        node_types = {}
        for node in ast.walk(self.ast_tree):
            node_type = type(node).__name__
            node_types[node_type] = node_types.get(node_type, 0) + 1
        
        self.statistics = {
            "total_nodes": sum(node_types.values()),
            "node_types": node_types,
            "functions": node_types.get('FunctionDef', 0) + node_types.get('AsyncFunctionDef', 0),
            "classes": node_types.get('ClassDef', 0),
            "imports": node_types.get('Import', 0) + node_types.get('ImportFrom', 0),
            "calls": node_types.get('Call', 0),
            "assignments": node_types.get('Assign', 0) + node_types.get('AnnAssign', 0),
            "if_statements": node_types.get('If', 0),
            "loops": node_types.get('For', 0) + node_types.get('While', 0),
            "try_blocks": node_types.get('Try', 0),
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get parsing statistics"""
        return self.statistics
    
    def print_statistics(self):
        """Print parsing statistics in human-readable format"""
        if not self.statistics:
            print("No statistics available. Run parse() first.")
            return
        
        if "error" in self.statistics:
            print(f"Syntax Error: {self.statistics['error']}")
            print(f"  Line {self.statistics['line']}, Column {self.statistics['offset']}")
            if self.statistics.get('text'):
                print(f"  {self.statistics['text']}")
            return
        
        print("PHASE 2: SYNTAX ANALYSIS STATISTICS")
        print("=" * 60)
        print(f"Total AST Nodes: {self.statistics['total_nodes']}")
        print(f"Functions: {self.statistics['functions']}")
        print(f"Classes: {self.statistics['classes']}")
        print(f"Imports: {self.statistics['imports']}")
        print(f"Function Calls: {self.statistics['calls']}")
        print(f"Assignments: {self.statistics['assignments']}")
        print(f"If Statements: {self.statistics['if_statements']}")
        print(f"Loops: {self.statistics['loops']}")
        print(f"Try Blocks: {self.statistics['try_blocks']}")
        
        print("\nNode Type Distribution:")
        for node_type, count in sorted(self.statistics['node_types'].items(), 
                                       key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {node_type:20} {count:4}")


def parse_python_source(source: str, filename: str = "<unknown>") -> ast.AST:
    """Convenience function to parse Python source code"""
    parser = PythonParser(source, filename)
    return parser.parse()


if __name__ == '__main__':
    # Example usage
    sample_code = '''
# Sample Python code
def hello(name: str) -> None:
    """Greet someone"""
    if name:
        message = f"Hello, {name}!"
        print(message)
    else:
        print("Hello, stranger!")
    
x = 42
y = 3.14
z = x + y * 2

class Calculator:
    def add(self, a, b):
        return a + b
'''
    
    parser = PythonParser(sample_code, "<example>")
    try:
        tree = parser.parse()
        parser.print_statistics()
        
        print("\n" + "=" * 60)
        print("AST Dump (first 500 characters):")
        print("=" * 60)
        ast_dump = ast.dump(tree, indent=2)
        print(ast_dump[:500] + "...")
        
    except SyntaxError as e:
        print(f"Failed to parse: {e}")
