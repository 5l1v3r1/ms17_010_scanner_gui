#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# __author__ = u'连天/信息技术部/北京分行/广发银行'
# __email__ = u"liantian@office.cgbchina"
# __status__ = "Dev"
#
# Copyright 2015-2016 liantian
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
# For more information, please refer to <http://unlicense.org>


import sys, os

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/lib")
import logging
import xlsxwriter
from appJar import gui
from time import sleep
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, wait, as_completed
import socket
import binascii



def get_tree_connect_request(ip, tree_id):
    ipc = "005c5c" + binascii.hexlify(ip) + "5c49504324003f3f3f3f3f00"
    ipc_len_hex = hex(len(ipc) / 2).replace("0x", "")
    smb = "ff534d4275000000001801280000000000000000000000000000729c" + binascii.hexlify(
        tree_id) + "c4e104ff00000000000100" + ipc_len_hex + "00" + ipc
    tree = "000000" + hex(len(smb) / 2).replace("0x", "") + smb
    tree_connect_request = binascii.unhexlify(tree)
    return tree_connect_request


def check(ip, port=445, timeout=3):
    negotiate_protocol_request = binascii.unhexlify(
        "00000054ff534d4272000000001801280000000000000000000000000000729c0000c4e1003100024c414e4d414e312e3000024c4d312e325830303200024e54204c414e4d414e20312e3000024e54204c4d20302e313200")
    session_setup_request = binascii.unhexlify(
        "0000008fff534d4273000000001801280000000000000000000000000000729c0000c4e10cff000000dfff0200010000000000310000000000d400008054004e544c4d5353500001000000050208a2010001002000000010001000210000002e3431426c7441314e505974624955473057696e646f7773203230303020323139350057696e646f7773203230303020352e3000")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.send(negotiate_protocol_request)
        s.recv(1024)
        s.send(session_setup_request)
        data = s.recv(1024)
        user_id = data[32:34]
        session_setup_request_2 = binascii.unhexlify(
            "00000150ff534d4273000000001801280000000000000000000000000000729c" + binascii.hexlify(
                user_id) + "c4e10cff000000dfff0200010000000000f200000000005cd0008015014e544c4d53535000030000001800180040000000780078005800000002000200d000000000000000d200000020002000d200000000000000f2000000050208a2ec893eacfc70bba9afefe94ef78908d37597e0202fd6177c0dfa65ed233b731faf86b02110137dc50101000000000000004724eed7b8d2017597e0202fd6177c0000000002000a0056004b002d005000430001000a0056004b002d005000430004000a0056004b002d005000430003000a0056004b002d00500043000700080036494bf1d7b8d20100000000000000002e003400310042006c007400410031004e005000590074006200490055004700300057696e646f7773203230303020323139350057696e646f7773203230303020352e3000")
        s.send(session_setup_request_2)
        s.recv(1024)
        session_setup_request_3 = binascii.unhexlify(
            "00000063ff534d4273000000001801200000000000000000000000000000729c0000c4e10dff000000dfff02000100000000000000000000000000400000002600002e0057696e646f7773203230303020323139350057696e646f7773203230303020352e3000")
        s.send(session_setup_request_3)
        data = s.recv(1024)
        tree_id = data[32:34]
        smb = get_tree_connect_request(ip, tree_id)
        s.send(smb)
        s.recv(1024)
        poc = binascii.unhexlify(
            "0000004aff534d422500000000180128000000000000000000000000" + binascii.hexlify(
                user_id) + "729c" + binascii.hexlify(
                tree_id) + "c4e11000000000ffffffff0000000000000000000000004a0000004a0002002300000007005c504950455c00")
        s.send(poc)
        data = s.recv(1024)
        if "\x05\x02\x00\xc0" in data:
            s.close()
            logging.info("{0}{1}".format(ip, "Critical ! ms17-010 check fail, need patch"))
            return ip, True, "Critical ! ms17-010 check fail, need patch"
        else:
            s.close()
            logging.info("{0}{1}".format(ip,  "Safety ! ms17-010 check success"))
            return ip, False, "Safety ! ms17-010 check success"
    except:
        logging.info("{0}{1}".format(ip,  "Doubtful ! maybe pc is shutdown"))
        return ip, None, "Doubtful ! maybe pc is shutdown"


def str2range(word):
    data = []
    b = word.split(",")
    for c in b:
        d = c.split("-")
        if len(d) == 1:
            data += d
        elif len(d) > 1:
            lis = range(int(d[0]), int(d[1]) + 1)
            data += ["{}".format(x) for x in lis]
    logging.info(word)
    logging.info(len(data))
    return data


def make_list(a, b, c, d):
    data = []
    for ip_a in a:
        for ip_b in b:
            for ip_c in c:
                for ip_d in d:
                    data.append("{0}.{1}.{2}.{3}".format(ip_a, ip_b, ip_c, ip_d))
    logging.info(len(data))
    return data


class MyApp(object):
    def __init__(self):
        self.app = gui()
        self._start = "Start"
        self._path = "Set WorkPath"
        self.save_path = None
        self.ip_address_list = None
        self._bg = None
        self._executor = None
        self._futures = []
        self.now = datetime.now().strftime("%y%m%d%H%M%S")

    def start_app(self):
        self.app.addLabel("title", "MS17-010 Scanner", 0, 0, 3)  # Row 0,Column 0,Span 2
        self.app.setFont(20, "Microsoft YaHei")
        self.app.setIcon("ico.ico")
        self.app.setTitle("MS17-010 Scanner")
        self.app.addLabel(title="ip1", text="IP Part 1:", row=1, column=0, colspan=1, rowspan=0)
        self.app.addLabel(title="ip2", text="IP Part 2:", row=2, column=0, colspan=1, rowspan=0)
        self.app.addLabel(title="ip3", text="IP Part 3:", row=3, column=0, colspan=1, rowspan=0)
        self.app.addLabel(title="ip4", text="IP Part 4:", row=4, column=0, colspan=1, rowspan=0)
        self.app.addLabel(title="path", text="Save Dir:", row=5, column=0, colspan=1, rowspan=0)
        self.app.addEntry(title="ip1", row=1, column=1, colspan=2, rowspan=0)
        self.app.addEntry(title="ip2", row=2, column=1, colspan=2, rowspan=0)
        self.app.addEntry(title="ip3", row=3, column=1, colspan=2, rowspan=0)
        self.app.addEntry(title="ip4", row=4, column=1, colspan=2, rowspan=0)
        self.app.addEntry(title="path", row=5, column=1, colspan=1, rowspan=0)
        self.app.setEntryState("path", "disabled")
        self.app.addButton(title=self._path, func=self.set_path, row=5, column=2, colspan=1, rowspan=0)

        self.app.setEntryDefault("ip1", "10,11")
        self.app.setEntryDefault("ip2", "74-75")
        self.app.setEntryDefault("ip3", "10-64,66")
        self.app.setEntryDefault("ip4", "241,245,1,2,3")
        self.app.setEntryDefault("path", u"注意反斜杠为正常现象")

        self.app.addMeter(name="progress", row=6, column=0, colspan=3, rowspan=0)
        self.app.addButton(title=self._start, func=self.start, row=7, column=0, colspan=0, rowspan=0)
        self.app.setButtonState(self._start, "disabled")
        self.app.go()

    def set_path(self, btnName):
        path = self.app.directoryBox()
        self.app.setEntry(name="path", text=path)
        self.app.setButtonState(self._start, "active")
        FORMAT = "%(asctime)s [%(levelname)s] [%(filename)s#%(lineno)d] %(message)s"
        logging.basicConfig(filename="{0}/ScanLog.log".format(path), level=logging.INFO, format=FORMAT)

    def start(self, btnName):
        self.now = datetime.now().strftime("%y%m%d%H%M%S")
        logging.info("===== Start Scan ===")
        logging.info("TIME_STAMP:{}".format(self.now))
        self.app.setButtonState(self._start, "disabled")
        self.app.setButtonState(self._path, "disabled")
        ip1 = str2range(self.app.getEntry("ip1"))
        ip2 = str2range(self.app.getEntry("ip2"))
        ip3 = str2range(self.app.getEntry("ip3"))
        ip4 = str2range(self.app.getEntry("ip4"))
        self.save_path = self.app.getEntry("path")
        self.ip_address_list = make_list(ip1, ip2, ip3, ip4)
        self.multi_scan()

    def multi_scan(self):

        self._executor = ThreadPoolExecutor(max_workers=10)
        self._futures = []
        for x in self.ip_address_list:
            self._futures.append(self._executor.submit(check, x))
        i = 1
        data = []
        for x in as_completed(self._futures):
            ip, r, d = x.result()
            data.append({"ip": ip, "r": str(r),"d":str(d)})
            self.app.setMeter("progress", value=int((i * 100) / len(self._futures)))
            i += 1

        workbook = xlsxwriter.Workbook('{0}/{1}_scan_result.xlsx'.format(self.save_path, self.now))
        worksheet = workbook.add_worksheet()
        worksheet.write_string(0, 0, "ip_address")
        worksheet.write_string(0, 1, "result")
        worksheet.write_string(0, 2, "data")
        row = 1
        col = 0
        for item in data:
            worksheet.write_string(row, col, item["ip"])
            worksheet.write_string(row, col + 1, item["r"])
            worksheet.write_string(row, col + 2, item["d"])
            row += 1
        workbook.close()
        self.app.infoBox("提示", "扫描完成")




if __name__ == "__main__":
    a = MyApp()
    a.start_app()
