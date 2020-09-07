import subprocess

useless_cat_call = subprocess.Popen(
    ["cat"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)
output, errors = useless_cat_call.communicate(input="Hello from the other side!")
useless_cat_call.wait()
print(output)
print(errors)
