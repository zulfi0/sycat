# sycat
sycat is netcat implementation in python3.

Reason why create this script ?
- tired of spawning pty shell and configure the terminal size every time get reverse shell connection while playing boot2root ctf.
- learn more about socket implementation.

# Update V0.3
due to compiling .exe binary now the script require `go` to be installed.

some update:
- Sycat V0.3 now support generating payload only in bash,nc, and exe.
- payload encoding (base64) currently support in bash and nc payload creation.
- auto spawn pty shell with options (-tty)
- bypass amsi is now supported with options (-amsi)

# Feature
Sycat currently support spawning pty shell and configure the terminal size automatically and also support:
-  read stdin as input.
-  support raw tty mode (stty raw -echo).
-  using built in python module (no need to install any module).
-  Sycat V0.3 now support generating payload only in bash,nc, and exe.
-  auto spawn pty shell with options (-tty)
-  bypass amsi is now supported with options (-amsi)

# Install 
Clone:
```bash
git clone https://github.com/zulfi0/sycat
```
Run the script:
```bash
chmod +x scat.py && ./scat.py --help
```

# Example
available options:

![image](https://github.com/zulfi0/sycat/assets/68773572/9a7a5f72-bb59-4ba2-9874-ea9b985a1c1e)

listen incoming connection:

![image](https://github.com/zulfi0/sycat/assets/68773572/239a6d44-e373-4918-b1d8-4b5d2c7c3c28)

spawning pty shell:

![image](https://github.com/zulfi0/sycat/assets/68773572/0d877094-cc08-45e8-8061-206c95c0e6ee)

# To do
- add powershell script payload and its obfuscate

#
If you have any suggestion or request feature or find any errors please create an issue.
