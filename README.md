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
available options:

![image](https://github.com/zulfi0/sycat/assets/68773572/f71d14fc-4d92-4332-be30-928d7f15c770)

listen incoming connection:

![image](https://github.com/zulfi0/sycat/assets/68773572/239a6d44-e373-4918-b1d8-4b5d2c7c3c28)

spawning pty shell:

![image](https://github.com/zulfi0/sycat/assets/68773572/0d877094-cc08-45e8-8061-206c95c0e6ee)

# To do
- add powershell script payload and its obfuscate

#
If you have any suggestion or request feature or find any errors please create an issue.
