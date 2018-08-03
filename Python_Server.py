#https://stackoverflow.com/questions/23828264/how-to-make-a-simple-multithreaded-socket-server-in-python-that-remembers-client
import socket
import threading
import datetime
import time
from time import gmtime, strftime


class bcolors:
        OKGREEN = '\033[92m'
        BOLD = '\033[1m'
        ENDC = '\033[0m'

class ThreadedServer(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def listen(self):
        self.sock.listen(5)
        while True:
            client, address = self.sock.accept()
            client.settimeout(60)
            threading.Thread(target = self.listenToClient,args = (client,address)).start()

    def listenToClient(self, client, address):
        size = 1024
        while True:
            try:
                data = client.recv(size)
                if data:
                    # Set the response to echo back the recieved data 
                    response = data
		    #timenow=datetime.datetime.now().time()
		    currenttime = time.localtime(time.time())
                    print bcolors.OKGREEN + bcolors.BOLD+"Client connected "+str(currenttime[3])+':'+str(currenttime[4])+':'+str(currenttime[5])+">"+bcolors.ENDC+" User %s from host %s in not currently inside or is logged of" % (response,address) 
                else:
                    raise error('Client disconnected')
            except:
                client.close()
                return False

if __name__ == "__main__":
    while True:
        port_num = input("Port? ")
        try:
            port_num = int(port_num)
            break
        except ValueError:
            pass

    ThreadedServer('',port_num).listen()