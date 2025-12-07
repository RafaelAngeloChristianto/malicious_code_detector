# Simple test file for demonstrating three-phase compilation

import sqlite3

def vulnerable_query(user_input):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # SQL injection vulnerability
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    cursor.execute(query)
    
    return cursor.fetchall()

# Test the function
result = vulnerable_query("admin")
print(result)
