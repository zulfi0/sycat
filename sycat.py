#!/usr/bin/env python3

import termios, tty
import threading
import logging
import argparse
import select
import socket
import sys
import os

'''
Socket Sections
'''
def listen(host, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try :
        server.bind((host, int(port)))
        logging.debug("Sycat: Version 0.2")
        logging.debug(f"Sycat: Listening on {host}:{port}")
        server.listen(1)
    except Exception:
        print(f"Sycat: Address already in use.")
        sys.exit(1)
    
    conn,addr = server.accept()
    logging.debug(f"Sycat: Connection from {addr[0]}")
    logging.debug(f"Sycat: Connection from {addr[0]}:{addr[1]}")

    return conn

#default is connect
def default(host, port):
    '''
    Connect to a server, still detect tty/pty terminal in case we connect to bind shell.
    use thread to receive data faster and receive continously.
    don't have to wait for user input for receiving data.
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    #STDIN check
    from_stdin, _, _ = select.select([sys.stdin], [], [], 0)

    try:
        host = socket.gethostbyname(host)
        s.connect((host,int(port)))
        logging.debug("Sycat: Version 0.1 beta")
        logging.debug(f"Sycat: Connected to {host}:{port}")

        t = threading.Thread(target=recv_data, args=(s,))
        t.start()

        #treat STDIN as our input and send it
        if from_stdin:
            file_data = sys.stdin.buffer.read()
            s.sendall(file_data)
            logging.debug(f'Sycat: {len(file_data)} bytes sent.')
            socket_closer(s)

        #Miscellanous feature goes here
        if args.upgrade:
            upgrade_shell(s)

        while True:
            #continously check terminal is in raw tty or not
            is_raw = stdin_israw()
            
            # Read input from terminal
            if is_raw:
                user_input = sys.stdin.buffer.read(1)
                s.send(user_input)
            else:
                user_input = sys.stdin.read(1)
                s.send(user_input.encode())

        socket_closer(s)

    except (Exception, ConnectionResetError, socket.error) as err:
        print(f'Sycat: {err}')
        s.close()
        sys.exit(1)

def recv_data(conn):
    '''
    receive big data at a time.
    output buffer instead decoding (in some case decoding is a bad idea specially when receiving binary data).
    '''

    buff = 8 * 1024
    data = ''

    while True:
        try:
            data = conn.recv(buff)
        except (ConnectionResetError, OSError):
            logging.debug('Sycat: Connection Reset by the client.')
            break

        if not data:
            logging.debug(f'Sycat: EOF reached.')
            break

        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()

    socket_closer(conn)

# shut and close the socket to prevent extra bytes when receiving binary data
def socket_closer(conn):
    '''
    os._exit() method in Python is used to exit the process 
    with specified status without calling cleanup handlers, flushing stdio buffers, kill all threads, etc. 
    '''
    try:
        conn.shutdown(socket.RDWR)
        conn.close()
    except:
        pass
        
    #os.EX_OK = 0
    os._exit(os.EX_OK)
    
'''
End of Socket Section
'''
############################################################

'''
Stdin Section (thanks to pwncat cytopia "https://github.com/cytopia/pwncat/blob/master/bin/pwncat#L3488")
Detect terminal mode:
'''
def stdin_israw():
    """Check if the terminal (STDIN) is set to raw mode."""
    fild = sys.stdin.fileno()
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

'''
End of stdin Section
'''

############################################################
'''
Miscellanous Section

'''
#upgrade shell (linux only)
def upgrade_shell(conn):
    #get size of current terminal
    rows = os.get_terminal_size().lines
    cols = os.get_terminal_size().columns
    
    logging.debug('Sycat: Spawning pty shell.')

    command = f"""export TERM=xterm; python3 -c 'import pty; pty.spawn("/bin/bash")' || python -c 'import pty; pty.spawn("/bin/bash")' || script -qc /bin/bash /dev/null"""
    command += '\n'
    conn.send(command.encode())

    logging.debug(f'Sycat: Configuring stty with rows {rows} and cols {cols}.\n')
    stty_command = f'stty rows {rows} cols {cols}\n'
    conn.send(stty_command.encode())

#try to bypass amsi (windows only)
def amsi_bypass(conn):
    return

'''
End of Miscellanous Section
'''

############################################################
'''
Handler Section
'''
def shell(conn):
    '''
    use thread to receive data faster and receive continously.
    don't have to wait for user input for receiving data.
    '''

    #Miscellanous feature goes here
    if args.upgrade:
        upgrade_shell(conn)

    #receive data and print to stdout
    t = threading.Thread(target=recv_data, args=(conn,))
    t.start()

    try:
        while True:
            #continously check terminal is in raw tty or not
            is_raw = stdin_israw()

            # Read input from terminal
            if is_raw:
                user_input = sys.stdin.buffer.read(1)
                conn.send(user_input)
            else:
                user_input = sys.stdin.read(1)
                conn.send(user_input.encode())
        
        socket_closer(conn)

    except socket.error as err:
        print(f'Sycat: {err}')
        sys.exit(1)

'''
End of Handler Section
'''
############################################################

if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(allow_abbrev=False,description="Sycat is a netcat implementation in python (by: sud0ku)")
    parser.add_argument("-p", "--port", required=True,help="port number to listen on")
    parser.add_argument("-host","--hostname",metavar="host",required=False, help="source ip for listening or connect to. default 0.0.0.0",default="0.0.0.0")
    parser.add_argument("-l","--listen",help="listen mode", action="store_true")
    parser.add_argument("-v", "--verbose", help="verbose output", action="store_true")
    parser.add_argument("-tty","--upgrade", help="auto spawn pty shell and configure the terminal size (linux only)", action="store_true")

    args = parser.parse_args()
    if args.verbose:
        logging.root.handlers = []
        logging.basicConfig(level=logging.DEBUG,format="%(message)s",)

    host = args.hostname
    port = args.port

    try :
        if args.listen:
            client = listen(host, port)
            s = threading.Thread(target=shell, args=(client,))
            s.start()
        else:
            default(host,port)
    except KeyboardInterrupt:
        os._exit(os.EX_OK)
