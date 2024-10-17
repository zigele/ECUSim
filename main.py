import json
import logging.config
import os
import threading
from datetime import datetime
from pathlib import Path

import can
import isotp

from uds import *
from uds_addtion import log_exception

os.add_dll_directory(Path(r"D:\Program Files (x86)\Vector License Client"))


class ECUSim:
    def __init__(self):
        self.stack = None
        self.lock = threading.RLock()

    @log_exception(logging.getLogger("app"))
    def start(self, interface, channel, bitrate, app_name, address_mode: isotp.AddressingMode, rxid, txid):
        bus = can.Bus(interface=interface, channel=channel, bitrate=bitrate, app_name=app_name)
        addr = isotp.Address(address_mode, rxid=rxid, txid=txid)
        params = {
            'blocking_send': True,
            'rx_flowcontrol_timeout': 5000,
            'rx_consecutive_frame_timeout': 5000,
        }
        self.stack = isotp.CanStack(bus, address=addr, params=params)
        self.stack.start()
        t1 = threading.Thread(target=self.__rev_thread, args=())  # 传个任务,和参数进来
        t1.daemon = False
        t1.start()

    def __rev_thread(self):
        while 1:
            if self.stack.available():
                rvdat = self.stack.recv()
                self._defaut_response(rvdat)

    @log_exception(logging.getLogger("app"))
    def _defaut_response(self, data: list):
        obj = eval(UDSService.get_name(data[0]))()
        if obj is not None:
            r = obj.process(data)
            if not r is None:
                self.stack.send(r, send_timeout=5000)
        else:
            logger.error("receive request SID:" + hex(data[0]) + " is not support.there not found class here.")


@log_exception(logging.getLogger("app"))
def setup_logging(default_path="logging.json", default_level=logging.INFO):
    if os.path.exists(default_path):
        with open(default_path, "r") as f:
            config = json.load(f)
            config['handlers']['file_handler']['filename'] = datetime.now().strftime('log/log_%Y-%m-%d.log')
            logging.config.dictConfig(config)
    else:
        logging.basicConfig(level=default_level)


if __name__ == '__main__':
    setup_logging(default_path="logconfig.json")
    logger = logging.getLogger("app")
    logger.info("app started!")

    ecu = ECUSim();
    ecu.start('vector', 0, 50000, 'python', isotp.AddressingMode.Normal_11bits, 0x7e0, 0x7e8)
