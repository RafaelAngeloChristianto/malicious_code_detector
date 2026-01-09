#!/usr/bin/env python3
"""
Test file to demonstrate Phase 3 Enhanced Semantic Analysis

This file contains various semantic issues to test:
1. Undefined variables
2. Duplicate definitions
3. Unused variables
4. Type mismatches
5. Missing return statements
6. High complexity
7. Unused parameters
"""

import os
import sys

# Test 1: Undefined variable
def test_undefined():
    x = 10
    y = undefined_variable + 5  # ERROR: undefined_variable not defined
    return y

# Test 2: Duplicate definition
def test_duplicate():
    value = 10
    value = 20  # OK: reassignment
    return value

def test_duplicate():  # ERROR: function already defined
    return 42

# Test 3: Unused variables
def test_unused():
    unused_local = 100  # WARNING: never used
    used_var = 200
    return used_var

# Test 4: Unused parameters
def test_unused_params(used, unused1, unused2):  # WARNING: unused1, unused2 never used
    return used * 2

# Test 5: Missing return statement
def test_missing_return(x):  # WARNING: may be missing return
    if x > 0:
        print("positive")
    else:
        print("not positive")
    # No return statement

# Test 6: High complexity function
def test_complexity(a, b, c, d, e):  # WARNING/ERROR: high complexity
    if a > 0:
        if b > 0:
            if c > 0:
                if d > 0:
                    if e > 0:
                        if a + b > 10:
                            if c + d > 10:
                                if e > 5:
                                    if a * b > 100:
                                        return True
    return False

# Test 7: Using variable before assignment in function scope
def test_scope():
    print(local_var)  # ERROR: local_var not defined yet
    local_var = 10
    return local_var

# Test 8: Class with unused attributes
class TestClass:
    def __init__(self, value):
        self.value = value
        self.unused_attr = 123  # WARNING: never used
    
    def get_value(self):
        return self.value
    
    def method_with_unused_param(self, param1, param2):  # WARNING: param2 unused
        return param1

# Test 9: Proper usage - no errors
def proper_function(x, y):
    """This function should have no semantic errors"""
    result = x + y
    if result > 10:
        return result * 2
    else:
        return result
    
# Test 10: Using built-ins (should not cause errors)
def test_builtins():
    numbers = list(range(10))
    text = str(len(numbers))
    print(text)
    return numbers

# Global unused variable
UNUSED_GLOBAL = "never used"

# Using undefined global
result = undefined_global_var * 2  # ERROR: undefined_global_var not defined

print("Semantic analysis test complete!")
