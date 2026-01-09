import ast

code = '''import jwt
token = jwt.encode({'user_id': 1}, "my_secret", algorithm='HS256')
'''

tree = ast.parse(code)
call_node = tree.body[1].value

print(f"Call type: {type(call_node.func)}")
print(f"Attr: {call_node.func.attr}")
print(f"Value: {call_node.func.value.id}")
print(f"Full name would be: {call_node.func.value.id}.{call_node.func.attr}")
