instal:
	- sudo pip3 install .

makainya gini:
```
from cryptbuf import *

e = cryptbuf_encrypt("asdasdasdasdasdasdasdasdasd", "john.doe@example.com")
print("e: " + e)
d = cryptbuf_decrypt(e, "john.doe@example.com")
print("d: " + d)
```