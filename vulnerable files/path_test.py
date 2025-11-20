# Test file for path traversal detection

import os

# Safe constant path
with open("safe.txt", "r") as f:
    pass

# Potential traversal with variable
user_input = input("Enter filename: ")
with open(user_input, "r") as f:  # Should flag as non-constant
    pass

# Explicit traversal in constant
with open("../secret.txt", "r") as f:  # Should flag as constant with ..
    pass

# os.path.join with variable
path = os.path.join("base", user_input)  # Non-constant
with open(path, "r") as f:
    pass

# Absolute path
with open("/etc/passwd", "r") as f:  # Absolute path
    pass