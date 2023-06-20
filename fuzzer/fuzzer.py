import sys
# sys.path.append("../fuzzer/") 
from scapy.all import *
from fuzzer.config import config
from fuzzer.log import log_info
from fuzzer.types import *
from queue import Queue
import binascii
import random
import threading
import time
import subprocess
from pwn import *


class Fuzzer(threading.Thread):
    def __init__(self, index, excq, template, targets, lock,n,thread_num):
        super(Fuzzer, self).__init__()
        self.index = index
        self.excq = excq
        self.template = template
        self.targets = targets
        self.shutdown = threading.Event()
        self.lock = lock
        self.n = n 
        self.thread_num=thread_num

    def run(self):
        try:
            self.lock.acquire()
            try:
                    print("\n")
                    success("第%d次Fuzz测试\n" % (self.n+self.thread_num))
                    payload = self.prepare()
                    self.send(payload,self.n)
            except Exception as e:
                self.excq.put(e)
            finally:
                self.lock.release()
        except Exception as e:
            self.excq.put(e)
    def res_error(self,sendinfo,last_payload):
            log.failure("Send ERROR")
            with open("./fuzz.log", 'a+') as file:
                file.write(str(sendinfo))
                file.write(str(last_payload))
                # file.write('-' *((16 -len(last_payload) % 16) % 16))
                file.close()
    def random_hex_integer(self, byte_string):
        num = int.from_bytes(byte_string, 'big')
        length = random.randint(0, 2)
        shift_count = 8 * (len(byte_string) - length)
        if shift_count <= 0:
            return num
        masked_num = num >> shift_count
        mask = (1 << (8 * length)) - 1
        masked_num &= mask
        return masked_num

    def prepare(self,type=0):
        value_fuzzs = {}
        targets = self.targets
        for target in targets:
            target = target[0]
            if self.shutdown.is_set():
                return
            fields = self.template[(True, config["Fuzzer"]["Layer"])]["fields"]
            index = random.choice(range(len(fields[target]["values"])))
            value = fields[target]["values"][index]#   
            p = subprocess.Popen(
                ["radamsa"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT
            )
            if isinstance(value, str):
                value_convert = binascii.unhexlify(value) # convert hex -> 48656c6c6f205365727669636521 to ascii -> b'Hello Service!'
            elif isinstance(value,int):
                # if target == "session_id":
                value_convert = str(value).encode()
            else:
                value_convert = value
            value_fuzz = p.communicate(input=value_convert)[0]
            # print(value_fuzz)
            if config["Fuzzer"]["History"] == "yes":
                log_info("Saving current fuzzing value as next seed")
                fields[target]["values"][index] = value_fuzz
            value_fuzzs[str(target)]=value_fuzz
        # print(value_fuzzs)
        return value_fuzzs

    def send(self,payload,n):
        global last_payload
        global last_payload0
        i = IP(src=config["Client"]["Host"], dst=config["Service"]["Host"])
        u = UDP(sport=config["Client"].getint("Port"), dport=config["Service"].getint("Port"))
        sip = SOMEIP()
        sip.iface_ver = 0
        sip.proto_ver = 1
        sip.msg_type = "REQUEST"
        sip.retcode = "E_OK"
        # try:
        if config["ServiceValue"]["srv_id"]=="fuzz":
            sip.srv_id = self.random_hex_integer(payload['srv_id'] )
        else:
            sip.srv_id = int(config["ServiceValue"]["srv_id"],16)
        if config["ServiceValue"]["sub_id"]=="fuzz":
            sip.sub_id = self.random_hex_integer(payload['sub_id'])
        else:
            sip.sub_id = int(config["ServiceValue"]["sub_id"],16)
        if config["ServiceValue"]["method_id"]=="fuzz":
            sip.method_id = self.random_hex_integer(payload['method_id']) 
        else:
            sip.method_id = int(config["ServiceValue"]["method_id"],16)
        if config["ServiceValue"]["client_id"]=="fuzz":
            sip.client_id = self.random_hex_integer(payload['client_id']) 
        else:
            sip.client_id = int(config["ServiceValue"]["client_id"],16)
        # if session_id==0:
        #     sip.session_id = int(config["ServiceValue"]["session_id"],16)
        # else:
        if config["ServiceValue"]["session_id"]=="fuzz":
            sip.session_id = self.random_hex_integer(payload['session_id'])
        else:
            sip.session_id = int(config["ServiceValue"]["session_id"],16)
        if config["ServiceValue"]["load"]=="fuzz":
            if payload['load']:sip.add_payload(Raw(payload['load']))
            # print(sip.add_payload)
        else:
            sip.add_payload(config["ServiceValue"]["load"].encode())
        paket = i/u/sip
        res = sr1(paket, retry=0, timeout=0.2, verbose=False)

        info("Sending Field: \n{}".format(sip.add_payload))
        if res==True:
            self.res_error(str(sip.add_payload),payload)
        # os.system("echo '{}\n' >> fuzz.log".format())
        
        # except:
        #         # self.res_error(str(sip.add_payload),payload)
        #     print("1")

if __name__ == "__main__":
    Fuzzer.test()