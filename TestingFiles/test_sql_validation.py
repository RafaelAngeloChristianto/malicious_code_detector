import ast
from phase3_LRparser import SemanticAnalyzer

# Test 1: Misspelled keyword
test_code1 = '''
def test():
    username = input('Username: ')
    query = "SELEC * FROM users WHERE name = '" + username + "'"
    class FakeCursor:
        def execute(self, q):
            pass
    cursor = FakeCursor()
    cursor.execute(query)
'''

# Test 2: Duplicate keywords
test_code2 = '''
def test():
    user_id = input("User ID: ")
    query = "SELECT SELECT SELECT SELECT * FROM users WHERE id = {}".format(user_id)
    class FakeCursor:
        def execute(self, q):
            pass
    cursor = FakeCursor()
    cursor.execute(query)
'''

print("TEST 1: Misspelled keyword (SELEC)")
print("="*70)
tree1 = ast.parse(test_code1, 'test.py')
analyzer1 = SemanticAnalyzer('test.py')
analyzer1.visit(tree1)
for finding in analyzer1.findings:
    print(f"{finding['severity']} - {finding['code']}: {finding['message']}")
print()

print("\nTEST 2: Duplicate consecutive keywords (SELECT SELECT SELECT)")
print("="*70)
tree2 = ast.parse(test_code2, 'test.py')
analyzer2 = SemanticAnalyzer('test.py')
analyzer2.visit(tree2)
for finding in analyzer2.findings:
    print(f"{finding['severity']} - {finding['code']}: {finding['message']}")
    if 'duplicate_keyword' in finding:
        print(f"  Duplicate: {finding['duplicate_keyword']}")
print()
