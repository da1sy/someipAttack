from scapy.all import *
from fuzzer.config import config
from fuzzer.log import log_info
from fuzzer.types import *
from queue import Queue
import threading
import time
from pwn import *

load_contrib("automotive.someip")

class Heartbeat(threading.Thread):

    def __init__(self, excq):
        super().__init__()
        self.excq = excq
        self.shutdown = threading.Event()
       
    def run(self):
        log.success("Heartbeat is started")
        while not self.shutdown.is_set():
            try:
                time.sleep(3)
                self.check()
            except PermissionError:
                self.excq.put(NoSudoError("Permission as sudo required to send SOME/IP pakets"))
        # log_info("Heartbeat is stopped")

    def check(self):
        try:
            i = IP(src=config["Client"]["Host"], dst=config["Service"]["Host"])
            u = UDP(sport=config["Client"].getint("Port"), dport=config["Service"].getint("Port"))
            sip = SOMEIP()
            sip.iface_ver = 0
            sip.proto_ver = 1
            sip.msg_type = "REQUEST"
            sip.retcode = "E_OK"
            sip.srv_id = int(config["ServiceValue"]["srv_id"],16)
            sip.sub_id = int(config["ServiceValue"]["sub_id"],16)
            sip.method_id= int(config["ServiceValue"]["method_id"],16)
            sip.client_id = int(config["ServiceValue"]["client_id"],16)
            sip.session_id = 0x0010
            sip.add_payload(Raw ("ping"))
            paket = i/u/sip
            res = sr1(paket, retry=0, timeout=3, verbose=False)
            if res == None:
                raise NoHostError(log.failure("No response received from SOME/IP host"))
            if res[Raw].load[-4:] != bytes("pong", "utf-8"):
                raise NoHeartbeatError(log.failure("No response received from SOME/IP host"))
        except (NoHostError, NoHeartbeatError) as exc:
                self.excq.put(exc)
