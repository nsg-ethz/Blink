import socket
import struct
import time
import subprocess, os , signal

def send_msg(sock, msg):

    msg = struct.pack('>I', len(msg)) + msg
    sock.sendall(msg)

def sendFlowTCP(dst="10.0.32.3",sport=5000,dport=5001,ipd=1,duration=0):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    #s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    #s.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 1500)

    s.bind(('', sport))

    try:
        reconnections = 5
        while reconnections:
            try:
                s.connect((dst, dport))
                break
            except:
                reconnections -=1
                print "TCP flow client could not connect with server... Reconnections left {0} ...".format(reconnections)
                time.sleep(0.5)

        #could not connect to the server
        if reconnections == 0:
            return

        totalTime = int(duration)

        startTime = time.time()
        i = 0
        time_step = 1
        while (time.time() - startTime <= totalTime):
            send_msg(s,"HELLO")
            i +=1
            next_send_time = startTime + i * ipd
            time.sleep(max(0,next_send_time - time.time()))

    except socket.error:
        pass

    finally:
        s.close()


def recvFlowTCP(dport=5001,**kwargs):

    """
    Lisitens on port dport until a client connects sends data and closes the connection. All the received
    data is thrown for optimization purposes.
    :param dport:
    :return:
    """

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    # s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    s.bind(("", dport))
    s.listen(1)
    conn = ''
    buffer = bytearray(4096)
    try:
        conn, addr = s.accept()
        while True:
            #data = recv_msg(conn)#conn.recv(1024)
            if not conn.recv_into(buffer,4096):
                break

    finally:
        if conn:
            conn.close()
        else:
            s.close()
