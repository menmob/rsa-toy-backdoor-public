# rsa-toy-backdoor-public


submit_server.sh will send 10 generated keypairs to the server and report back to you if they were successfully cracked or not.

**To compile on Mac (install brew if needed):**
```bash
brew install openssl@3

gcc -o rsa_gen main.c -Wdeprecated-declarations -Wall -O2 -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lcrypto

./rsa_gen
```

**To compile on Linux:**

Install OpenSSL 3+ with whatever package manager
```bash
gcc -o rsa_gen main.c -Wdeprecated-declarations -Wall -O2 -lcrypto

./rsa_gen
```

**To compile on Windows:**

SSH into a WPI Linux server, then follow Linux instructions (sorry not sorry)

