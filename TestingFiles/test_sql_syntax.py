#!/usr/bin/env python3
"""
Test file for SQL syntax error detection

This file contains intentional SQL syntax errors (typos) that should be detected
by the enhanced semantic analyzer.
"""

import sqlite3

# Test 1: Misspelled SELECT
def test_select_typo():
    query = "SELCT * FROM users"  # ERROR: SELCT should be SELECT
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()

# Test 2: Misspelled FROM  
def test_from_typo():
    query = "SELECT * FORM users WHERE id = 1"  # ERROR: FORM should be FROM
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()

# Test 3: Misspelled WHERE
def test_where_typo():
    query = "SELECT name FROM users WHER age > 18"  # ERROR: WHER should be WHERE
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()

# Test 4: Misspelled INSERT
def test_insert_typo():
    query = "INSRT INTO users (name, age) VALUES ('John', 25)"  # ERROR: INSRT should be INSERT
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(query)
    conn.commit()

# Test 5: Misspelled UPDATE
def test_update_typo():
    query = "UPDTE users SET age = 26 WHERE name = 'John'"  # ERROR: UPDTE should be UPDATE
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(query)
    conn.commit()

# Test 6: Misspelled DELETE
def test_delete_typo():
    query = "DELET FROM users WHERE id = 1"  # ERROR: DELET should be DELETE
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(query)
    conn.commit()

# Test 7: Missing space - SELECTFROM
def test_missing_space_1():
    query = "SELECTFROM users"  # ERROR: Missing space between SELECT and FROM
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()

# Test 8: Missing space - INSERTINTO
def test_missing_space_2():
    query = "INSERTINTO users (name) VALUES ('Jane')"  # ERROR: Missing space
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(query)
    conn.commit()

# Test 9: Missing space - DELETEFROM
def test_missing_space_3():
    query = "DELETEFROM users WHERE name = 'Jane'"  # ERROR: Missing space
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(query)
    conn.commit()

# Test 10: Multiple errors in one query
def test_multiple_errors():
    # Multiple errors: SELCT, FORM, WHER
    query = "SELCT name FORM users WHER age > 21"
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()

# Test 11: Correct SQL (should not generate errors)
def test_correct_sql():
    query = "SELECT * FROM users WHERE age > 18 ORDER BY name"  # No errors
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()

# Test 12: JOIN typo
def test_join_typo():
    query = "SELECT u.name FROM users u JION orders o ON u.id = o.user_id"  # ERROR: JION should be JOIN
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()

# Test 13: ORDER BY without space
def test_orderby_typo():
    query = "SELECT * FROM users ORDERBY age"  # ERROR: Missing space
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()

# Test 14: GROUP BY without space
def test_groupby_typo():
    query = "SELECT age, COUNT(*) FROM users GROUPBY age"  # ERROR: Missing space
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()

# Test 15: Complex query with typo
def test_complex_typo():
    query = """
    SELCT u.name, COUNT(o.id) as order_count
    FORM users u
    LEFT JION orders o ON u.id = o.user_id
    WHER u.active = 1
    GROUP BY u.name
    HAVING COUNT(o.id) > 0
    ODER BY order_count DESC
    """
    # Errors: SELCT, FORM, JION, WHER, ODER
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()

if __name__ == "__main__":
    print("SQL Syntax Error Test Cases")
    print("=" * 60)
    print("This file contains intentional SQL syntax errors.")
    print("Run the semantic analyzer to detect them!")
