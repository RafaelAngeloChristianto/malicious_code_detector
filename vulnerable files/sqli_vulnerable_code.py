def insecure_get_user_rows(username):
    # ❌ Vulnerable: string concatenation → SQL injection risk
    query = "SELECT * FROM users WHERE username = '" + username + "';"
    print("QUERY:", query)
    # (imagine executing query against a DB)
    return query
