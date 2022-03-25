import abc
import logging

import re
import tempfile
from enum import Enum, IntEnum
from trace import Direction, PacketType, TraceAnalyzer, get_direction, get_packet_type
from typing import List, Optional

from Crypto.Cipher import AES

from result import TestResult
from testcases import TestCase, TestCaseHandshake
import testcases

KB = 1 << 10
MB = 1 << 20

QUIC_DRAFT = 34  # draft-34
QUIC_VERSION = hex(0x1)


class Perspective(Enum):
    SERVER = "server"
    CLIENT = "client"
    ATTACKER = "attacker"

class AttackTarget(Enum):
    SERVER = "server"
    CLIENT = "client"
    BOTH = "both"

class Attack(TestCase):
    _attacker_log_dir = None
    
    def __init__(
        self,
        sim_log_dir: tempfile.TemporaryDirectory,
        attacker_log_dir: tempfile.TemporaryDirectory,
        client_keylog_file: str,
        server_keylog_file: str,
    ):
        self._attacker_log_dir = attacker_log_dir
        super().__init__(sim_log_dir, client_keylog_file, server_keylog_file)
        
    def certs_dir(self):
        if not self._cert_dir:
            self._cert_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="certs_")
            testcases.generate_cert_chain(self._cert_dir.name)
        return self._cert_dir.name + "/"
    
    @abc.abstractmethod
    def target(self) -> AttackTarget:
        pass
class AttackInitFlood(Attack):
    
    @staticmethod
    def name():
        return "initflood"

    @staticmethod
    def testname(p: Perspective):
        return TestCaseHandshake.name()
    
    @staticmethod
    def abbreviation():
        return "IF"
    

    @staticmethod
    def desc():
        return "Flood a server with initial packets using a single IP spoofed endpoint"

    @staticmethod
    def timeout() -> int:
        return 15
    
    @staticmethod
    def target() -> AttackTarget:
        return AttackTarget.SERVER
    
    def get_paths(self):
        return [""]
    
    def check(self) -> TestResult:
        attack_log_file = self._attacker_log_dir.name + f"/{self.name()}.log"
        log = open(attack_log_file, "r")
        reg_exp = r"\d{0,1}\d\.\d\d\%"
        # exponential moving average
        ema = 0
        n = 0
        for line in log:
            line_value = re.search(reg_exp, line)
            if line_value:
                cpu_usage = float(line_value.group()[:-1])
                k = (2/(n+1))
                ema = k*cpu_usage + ema*(1-k)
                n +=1
                logging.debug("cpu usage: " + str(cpu_usage) + ", EMA: " + str(ema))
                if cpu_usage >= 20 or ema >= 15:
                    return TestResult.SUCCEEDED
        return TestResult.FAILED
        
        
ATTACKS = [
    AttackInitFlood,
]