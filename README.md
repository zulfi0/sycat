# sycat
sycat is netcat implementation in python3.

Reason why create this script ?
- tired of spawning pty shell and configure the terminal size every time get reverse shell connection while playing boot2root ctf.
- learn more about socket implementation.

# Update V0.4
due to compiling .exe binary now the script require `go` to be installed and `upx` for compressing the exe payload.

some update:
- now support listen or connect with ssl `(--ssl)`.
- change the encode options to `(-en)` instead of `(-e)`.
- execute command to execute for listen or connect is now supported.
- options `-host` and `-p` to specify ip and port is now changed to positional argument, where the default value of ip is `0.0.0.0`

# Feature
Sycat currently support spawning pty shell and configure the terminal size automatically and also support:
-  read stdin as input.
-  support raw tty mode (stty raw -echo).
-  using built in python module (no need to install any module).
-  support generating payload only in bash,nc, and exe.
-  auto spawn pty shell and configure the terminal size automatically with options (-tty)
-  bypass amsi is supported with options (-amsi)
-  ssl is now supported !
-  execute command to  execute for listen or connect.

# Known Issue
- options `-e` to execute command for listen or connect currently not compatible with --ssl.

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
listen incoming connection:
```bash
./scat.py -vl 1337
```

auto spawning pty shell when received reverse shell connection:
```bash
./scat.py -vl 1337 -tty
```

auto spawning pty shell when connected to bind shell connection:
```bash
./scat.py -v 127.0.0.1 1337 -tty
```
to listen with `SSL` first generate the key and cert file:
```bash
openssl req -x509 -newkey rsa:4096 -keyout server-key.pem -out server-cert.pem -days 365 -nodes
```
listen with ssl key and cert file:
```bash
sycat -vl 1337 --ssl --ssl-key server-key.pem --ssl-cert server-cert.pem
```

or connect with ssl:
```bash
sycat -v 127.0.0.1 1337 --ssl --ssl-key server-key.pem --ssl-cert server-cert.pem
```

# To do
- add powershell script payload and its obfuscate

#
If you have any suggestion or request feature or find any errors please create an issue.
