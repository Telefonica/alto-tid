"""
Module to manage exaBGP speaker:
- Set neighbor speakers and config
- Start speaker
- Retrieve RIB information
"""
import socket
import subprocess
import shlex

IP_BGP_RR = ['50.50.50.1', '60.60.60.1']
BGP_PORT = 179


def split_command(cmd):
    """split command with shlex"""
    return shlex.split(cmd)


class ManageBGPSpeaker:

    def start(self):
        """ Start exabgp """
        subprocess.run(split_command('service exabgp start'))
    
    @staticmethod
    def check_service_running():
        cmd = subprocess.run(split_command('systemctl is-active exabgp'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return 0 if b'active' in cmd.stdout else 1
    
    @staticmethod
    def get_journal():
        """ Get journalctl logs to read the routes from the speaker"""
        cmd = split_command('journalctl -f')
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def start_and_get_journal(self):
        self.start()
        if self.check_service_running() == 0:
            return self.get_journal()
        raise Exception("Service exabgp is not running. Check status")

    def check_tcp_connection(self):
        """checks if tcp on port 179 against route reflectors is established"""
        for ip_address in IP_BGP_RR:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print(f"IP ADDRESS {ip_address} port {BGP_PORT}")
            sock.connect((ip_address, BGP_PORT))
            try:
                sock.send(b'is alive')
                self.shutdown()
                return self.start_and_get_journal()
            except socket.error:
                return self.start_and_get_journal()

    @staticmethod
    def shutdown():
        cmd = split_command('service exabgp stop')
        subprocess.run(cmd)
