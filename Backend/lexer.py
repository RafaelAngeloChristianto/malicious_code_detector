"""
Python Lexer - Tokenizes Python source code
============================================
This lexer breaks down Python source code into tokens for analysis.
"""

import re
from enum import Enum, auto
from dataclasses import dataclass
from typing import List, Optional


class TokenType(Enum):
    """Token types for Python source code"""
    # Keywords
    KEYWORD = auto()
    
    # Identifiers and Literals
    IDENTIFIER = auto()
    NUMBER = auto()
    STRING = auto()
    
    # Operators
    PLUS = auto()
    MINUS = auto()
    STAR = auto()
    SLASH = auto()
    DOUBLE_SLASH = auto()
    PERCENT = auto()
    DOUBLE_STAR = auto()
    AT = auto()
    
    # Comparison
    EQ = auto()
    NE = auto()
    LT = auto()
    LE = auto()
    GT = auto()
    GE = auto()
    
    # Logical
    AND = auto()
    OR = auto()
    NOT = auto()
    
    # Bitwise
    AMPERSAND = auto()
    PIPE = auto()
    CARET = auto()
    TILDE = auto()
    LSHIFT = auto()
    RSHIFT = auto()
    
    # Assignment
    ASSIGN = auto()
    PLUS_ASSIGN = auto()
    MINUS_ASSIGN = auto()
    STAR_ASSIGN = auto()
    SLASH_ASSIGN = auto()
    PERCENT_ASSIGN = auto()
    DOUBLE_STAR_ASSIGN = auto()
    DOUBLE_SLASH_ASSIGN = auto()
    AMPERSAND_ASSIGN = auto()
    PIPE_ASSIGN = auto()
    CARET_ASSIGN = auto()
    LSHIFT_ASSIGN = auto()
    RSHIFT_ASSIGN = auto()
    AT_ASSIGN = auto()
    WALRUS = auto()  # :=
    
    # Delimiters
    LPAREN = auto()
    RPAREN = auto()
    LBRACKET = auto()
    RBRACKET = auto()
    LBRACE = auto()
    RBRACE = auto()
    COMMA = auto()
    COLON = auto()
    SEMICOLON = auto()
    DOT = auto()
    ARROW = auto()
    ELLIPSIS = auto()
    
    # Special
    NEWLINE = auto()
    INDENT = auto()
    DEDENT = auto()
    COMMENT = auto()
    EOF = auto()
    WHITESPACE = auto()
    
    # Error
    ERROR = auto()


@dataclass
class Token:
    """Represents a single token"""
    type: TokenType
    value: str
    line: int
    column: int
    
    def __repr__(self):
        return f"Token({self.type.name}, {self.value!r}, {self.line}:{self.column})"


class PythonLexer:
    """Lexer for tokenizing Python source code"""
    
    # Python keywords
    KEYWORDS = {
        'False', 'None', 'True', 'and', 'as', 'assert', 'async', 'await',
        'break', 'class', 'continue', 'def', 'del', 'elif', 'else', 'except',
        'finally', 'for', 'from', 'global', 'if', 'import', 'in', 'is',
        'lambda', 'nonlocal', 'not', 'or', 'pass', 'raise', 'return',
        'try', 'while', 'with', 'yield'
    }
    
    def __init__(self, source: str):
        self.source = source
        self.pos = 0
        self.line = 1
        self.column = 1
        self.tokens: List[Token] = []
        self.indent_stack = [0]
        
    def current_char(self) -> Optional[str]:
        """Get current character without advancing"""
        if self.pos >= len(self.source):
            return None
        return self.source[self.pos]
    
    def peek_char(self, offset: int = 1) -> Optional[str]:
        """Peek ahead at character"""
        pos = self.pos + offset
        if pos >= len(self.source):
            return None
        return self.source[pos]
    
    def advance(self) -> Optional[str]:
        """Move to next character"""
        if self.pos >= len(self.source):
            return None
        char = self.source[self.pos]
        self.pos += 1
        if char == '\n':
            self.line += 1
            self.column = 1
        else:
            self.column += 1
        return char
    
    def skip_whitespace(self) -> bool:
        """Skip whitespace (but not newlines). Returns True if any was skipped."""
        skipped = False
        while self.current_char() in ' \t\r':
            self.advance()
            skipped = True
        return skipped
    
    def read_comment(self) -> Token:
        """Read a comment token"""
        start_line = self.line
        start_col = self.column
        value = ''
        
        while self.current_char() and self.current_char() != '\n':
            value += self.advance()
        
        return Token(TokenType.COMMENT, value, start_line, start_col)
    
    def read_string(self) -> Token:
        """Read string literal (single, double, or triple quoted)"""
        start_line = self.line
        start_col = self.column
        quote = self.current_char()
        value = self.advance()  # Opening quote
        
        # Check for triple quotes
        if self.current_char() == quote and self.peek_char() == quote:
            value += self.advance()  # Second quote
            value += self.advance()  # Third quote
            triple = True
            end_seq = quote * 3
        else:
            triple = False
            end_seq = quote
        
        escaped = False
        while self.current_char():
            char = self.current_char()
            
            if escaped:
                value += self.advance()
                escaped = False
            elif char == '\\':
                value += self.advance()
                escaped = True
            elif triple:
                # Check for triple quote ending
                if (char == quote and 
                    self.peek_char() == quote and 
                    self.peek_char(2) == quote):
                    value += self.advance()
                    value += self.advance()
                    value += self.advance()
                    break
                else:
                    value += self.advance()
            else:
                if char == quote:
                    value += self.advance()
                    break
                else:
                    value += self.advance()
        
        return Token(TokenType.STRING, value, start_line, start_col)
    
    def read_number(self) -> Token:
        """Read numeric literal"""
        start_line = self.line
        start_col = self.column
        value = ''
        
        # Handle different number formats
        if self.current_char() == '0':
            value += self.advance()
            # Binary
            if self.current_char() in 'bB':
                value += self.advance()
                while self.current_char() in '01_':
                    value += self.advance()
            # Octal
            elif self.current_char() in 'oO':
                value += self.advance()
                while self.current_char() in '01234567_':
                    value += self.advance()
            # Hexadecimal
            elif self.current_char() in 'xX':
                value += self.advance()
                while self.current_char() and (self.current_char().isdigit() or 
                                              self.current_char() in 'abcdefABCDEF_'):
                    value += self.advance()
            # Float starting with 0
            elif self.current_char() == '.':
                value += self.advance()
                while self.current_char() and self.current_char().isdigit():
                    value += self.advance()
        else:
            # Regular number
            while self.current_char() and (self.current_char().isdigit() or 
                                          self.current_char() == '_'):
                value += self.advance()
            
            # Check for float
            if self.current_char() == '.':
                value += self.advance()
                while self.current_char() and self.current_char().isdigit():
                    value += self.advance()
        
        # Check for exponent
        if self.current_char() in 'eE':
            value += self.advance()
            if self.current_char() in '+-':
                value += self.advance()
            while self.current_char() and self.current_char().isdigit():
                value += self.advance()
        
        # Check for imaginary
        if self.current_char() in 'jJ':
            value += self.advance()
        
        return Token(TokenType.NUMBER, value, start_line, start_col)
    
    def read_identifier(self) -> Token:
        """Read identifier or keyword"""
        start_line = self.line
        start_col = self.column
        value = ''
        
        while self.current_char() and (self.current_char().isalnum() or 
                                      self.current_char() == '_'):
            value += self.advance()
        
        # Check if it's a keyword
        if value in self.KEYWORDS:
            return Token(TokenType.KEYWORD, value, start_line, start_col)
        
        return Token(TokenType.IDENTIFIER, value, start_line, start_col)
    
    def read_operator(self) -> Token:
        """Read operator or delimiter"""
        start_line = self.line
        start_col = self.column
        char = self.current_char()
        next_char = self.peek_char()
        next_next = self.peek_char(2)
        
        # Three-character operators
        if char == '.' and next_char == '.' and next_next == '.':
            self.advance()
            self.advance()
            self.advance()
            return Token(TokenType.ELLIPSIS, '...', start_line, start_col)
        elif char == '/' and next_char == '/' and next_next == '=':
            self.advance()
            self.advance()
            self.advance()
            return Token(TokenType.DOUBLE_SLASH_ASSIGN, '//=', start_line, start_col)
        elif char == '*' and next_char == '*' and next_next == '=':
            self.advance()
            self.advance()
            self.advance()
            return Token(TokenType.DOUBLE_STAR_ASSIGN, '**=', start_line, start_col)
        elif char == '<' and next_char == '<' and next_next == '=':
            self.advance()
            self.advance()
            self.advance()
            return Token(TokenType.LSHIFT_ASSIGN, '<<=', start_line, start_col)
        elif char == '>' and next_char == '>' and next_next == '=':
            self.advance()
            self.advance()
            self.advance()
            return Token(TokenType.RSHIFT_ASSIGN, '>>=', start_line, start_col)
        
        # Two-character operators
        two_char_ops = {
            '==': TokenType.EQ,
            '!=': TokenType.NE,
            '<=': TokenType.LE,
            '>=': TokenType.GE,
            '<<': TokenType.LSHIFT,
            '>>': TokenType.RSHIFT,
            '**': TokenType.DOUBLE_STAR,
            '//': TokenType.DOUBLE_SLASH,
            '+=': TokenType.PLUS_ASSIGN,
            '-=': TokenType.MINUS_ASSIGN,
            '*=': TokenType.STAR_ASSIGN,
            '/=': TokenType.SLASH_ASSIGN,
            '%=': TokenType.PERCENT_ASSIGN,
            '&=': TokenType.AMPERSAND_ASSIGN,
            '|=': TokenType.PIPE_ASSIGN,
            '^=': TokenType.CARET_ASSIGN,
            '@=': TokenType.AT_ASSIGN,
            '->': TokenType.ARROW,
            ':=': TokenType.WALRUS,
        }
        
        two_char = char + (next_char or '')
        if two_char in two_char_ops:
            self.advance()
            self.advance()
            return Token(two_char_ops[two_char], two_char, start_line, start_col)
        
        # Single-character operators
        single_char_ops = {
            '+': TokenType.PLUS,
            '-': TokenType.MINUS,
            '*': TokenType.STAR,
            '/': TokenType.SLASH,
            '%': TokenType.PERCENT,
            '@': TokenType.AT,
            '<': TokenType.LT,
            '>': TokenType.GT,
            '=': TokenType.ASSIGN,
            '&': TokenType.AMPERSAND,
            '|': TokenType.PIPE,
            '^': TokenType.CARET,
            '~': TokenType.TILDE,
            '(': TokenType.LPAREN,
            ')': TokenType.RPAREN,
            '[': TokenType.LBRACKET,
            ']': TokenType.RBRACKET,
            '{': TokenType.LBRACE,
            '}': TokenType.RBRACE,
            ',': TokenType.COMMA,
            ':': TokenType.COLON,
            ';': TokenType.SEMICOLON,
            '.': TokenType.DOT,
        }
        
        if char in single_char_ops:
            self.advance()
            return Token(single_char_ops[char], char, start_line, start_col)
        
        # Unknown character
        self.advance()
        return Token(TokenType.ERROR, char, start_line, start_col)
    
    def tokenize(self) -> List[Token]:
        """Tokenize the entire source code"""
        while self.pos < len(self.source):
            # Skip whitespace (but not newlines)
            self.skip_whitespace()
            
            char = self.current_char()
            
            if char is None:
                break
            
            # Newline
            if char == '\n':
                token = Token(TokenType.NEWLINE, char, self.line, self.column)
                self.tokens.append(token)
                self.advance()
            
            # Comment
            elif char == '#':
                self.tokens.append(self.read_comment())
            
            # String literals
            elif char in '"\'':
                # Check for raw/formatted strings
                prev_pos = self.pos - 1
                prefix = ''
                if prev_pos >= 0 and self.source[prev_pos] in 'rRfFbBuU':
                    prefix = self.source[prev_pos]
                self.tokens.append(self.read_string())
            
            # Numbers
            elif char.isdigit():
                self.tokens.append(self.read_number())
            
            # Identifiers and keywords
            elif char.isalpha() or char == '_':
                self.tokens.append(self.read_identifier())
            
            # Operators and delimiters
            else:
                self.tokens.append(self.read_operator())
        
        # Add EOF token
        self.tokens.append(Token(TokenType.EOF, '', self.line, self.column))
        
        return self.tokens
    
    def filter_tokens(self, exclude_types: set = None) -> List[Token]:
        """Return tokens excluding specified types (e.g., comments, whitespace)"""
        if exclude_types is None:
            exclude_types = {TokenType.COMMENT, TokenType.WHITESPACE}
        
        return [token for token in self.tokens if token.type not in exclude_types]


def tokenize_python_source(source: str) -> List[Token]:
    """Convenience function to tokenize Python source code"""
    lexer = PythonLexer(source)
    return lexer.tokenize()


if __name__ == '__main__':
    # Example usage
    sample_code = '''
# Sample Python code
def hello(name: str) -> None:
    """Greet someone"""
    message = f"Hello, {name}!"
    print(message)
    
x = 42
y = 3.14
z = x + y * 2
'''
    
    lexer = PythonLexer(sample_code)
    tokens = lexer.tokenize()
    
    print("Tokens:")
    print("-" * 60)
    for token in tokens:
        if token.type not in {TokenType.WHITESPACE, TokenType.NEWLINE}:
            print(token)
    
    print("\n" + "=" * 60)
    print(f"Total tokens: {len(tokens)}")
    print(f"Keywords: {len([t for t in tokens if t.type == TokenType.KEYWORD])}")
    print(f"Identifiers: {len([t for t in tokens if t.type == TokenType.IDENTIFIER])}")
    print(f"Numbers: {len([t for t in tokens if t.type == TokenType.NUMBER])}")
    print(f"Strings: {len([t for t in tokens if t.type == TokenType.STRING])}")
