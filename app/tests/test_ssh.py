import os
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import paramiko
from transport import SSH

class Server(paramiko.ServerInterface):
    def check_auth_password(self,user,password):return paramiko.AUTH_SUCCESSFUL if (user,password)==('fixture','fixture')else paramiko.AUTH_FAILED
    def get_allowed_auths(self,user):return 'password'
    def check_channel_request(self,kind,chanid):return paramiko.OPEN_SUCCEEDED
    def check_channel_exec_request(self,channel,command):return True

class SshTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.env=patch.dict(os.environ,{'VLESS_MANAGER_DATA':self.tmp.name});self.env.start()
        self.key=paramiko.RSAKey.generate(2048);self.stop=threading.Event();self.sock=socket.socket();self.sock.bind(('127.0.0.1',0));self.sock.listen(4);self.sock.settimeout(.2)
        self.port=self.sock.getsockname()[1];self.transports=[];self.thread=threading.Thread(target=self.serve,daemon=True);self.thread.start()
    def serve(self):
        while not self.stop.is_set():
            try:client,_=self.sock.accept()
            except socket.timeout:continue
            except OSError:return
            threading.Thread(target=self.handle,args=(client,self.key),daemon=True).start()
    def handle(self,client,key):
        transport=paramiko.Transport(client);self.transports.append(transport)
        try:
            transport.add_server_key(key);transport.start_server(server=Server());ch=transport.accept(5)
            if ch:
                data=bytearray()
                while True:
                    part=ch.recv(32768)
                    if not part:break
                    data.extend(part)
                ch.sendall(b'READ_ONLY:'+bytes(data));ch.send_exit_status(0);time.sleep(.1);ch.close()
        except (EOFError,OSError,paramiko.SSHException):pass
        finally:transport.close()
    def tearDown(self):
        self.stop.set();self.sock.close()
        for t in self.transports:t.close()
        self.thread.join(2);self.env.stop();self.tmp.cleanup()
    def ssh(self,confirm):return SSH({'host':'127.0.0.1','port':str(self.port),'username':'fixture'},'fixture',confirm)
    def test_unknown_key_requires_confirmation(self):
        prompts=[];ssh=self.ssh(lambda title,text:prompts.append(text)or True)
        try:self.assertEqual(ssh.command('fixture','payload'),'READ_ONLY:payload');self.assertEqual(len(prompts),1);self.assertIn('SHA256:',prompts[0])
        finally:ssh.close()
    def test_unknown_key_can_be_rejected(self):
        ssh=self.ssh(lambda *a:False)
        try:
            with self.assertRaisesRegex(RuntimeError,'не подтверждён'):ssh.connect()
        finally:ssh.close()
    def test_changed_key_never_silently_accepted(self):
        ssh=self.ssh(lambda *a:True)
        ssh.connect();ssh.close();self.key=paramiko.RSAKey.generate(2048)
        ssh=self.ssh(lambda *a:True)
        try:
            with self.assertRaises(paramiko.BadHostKeyException):ssh.connect()
        finally:ssh.close()

if __name__=='__main__':unittest.main()
