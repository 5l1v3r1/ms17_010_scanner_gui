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


import os
import sys

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/lib")
import logging
import xlsxwriter
from appJar import gui
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed, ProcessPoolExecutor

from checker import checker

logging.basicConfig(filename="ScanLog.log", level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] [%(filename)s#%(lineno)d] %(message)s")
logging.getLogger().addHandler(logging.StreamHandler())


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


def save_date(data, work_dir="."):
    workbook = xlsxwriter.Workbook('{0}/scan_result_{1}.xlsx'.format(work_dir, datetime.now().strftime("%y%m%d%H%M%S")))
    worksheet = workbook.add_worksheet()
    worksheet.write_string(0, 0, "ip_address")
    worksheet.write_string(0, 1, "result")
    worksheet.write_string(0, 2, "data")
    row = 1
    col = 0
    for item in data:
        worksheet.write_string(row, col, item[0])
        worksheet.write_string(row, col + 1, item[1])
        worksheet.write_string(row, col + 2, item[2])
        row += 1
    workbook.close()


def multi_scan(ip_list, work_dir="."):
    data = []
    futures = []
    executor = ProcessPoolExecutor(max_workers=100)

    for ip in ip_list:
        futures.append(executor.submit(checker, ip))

    for x in as_completed(futures):
        ip, r, d = x.result()
        data.append([ip, str(r), str(d)])
        logging.info("{0:>5}/{1:<5} IP: {2:<15} RESULT:{3}".format(len(data), len(futures), ip, d))
    save_date(data=data, work_dir=work_dir)


def scan_txt(filename):
    with open(filename) as f:
        ip_list = f.read().splitlines()
    multi_scan(ip_list)

class MyApp(object):
    def __init__(self):
        self.app = gui()
        self._start = "Start"
        self._path = "Set WorkPath"
        self.save_path = None
        self.ip_address_list = None
        self.now = datetime.now().strftime("%y%m%d%H%M%S")
        self._bg = None
        # self._executor = ThreadPoolExecutor(max_workers=30)
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
        self.app.setEntryDefault("path", "d://path/to/save/result/")
        self.app.addButton(title=self._start, func=self.start, row=6, column=0, colspan=0, rowspan=0)
        self.app.setButtonState(self._start, "disabled")
        self.app.go()

    def set_path(self, btnName):
        path = self.app.directoryBox()
        self.app.setEntry(name="path", text=path)
        self.app.setButtonState(self._start, "active")

    def start(self, btnName):
        self.now = datetime.now().strftime("%y%m%d%H%M%S")
        logging.info("===== Start Scan ===")
        logging.info("TIME_STAMP:{}".format(self.now))
        ip1 = str2range(self.app.getEntry("ip1"))
        ip2 = str2range(self.app.getEntry("ip2"))
        ip3 = str2range(self.app.getEntry("ip3"))
        ip4 = str2range(self.app.getEntry("ip4"))
        self.save_path = self.app.getEntry("path")
        self.ip_address_list = make_list(ip1, ip2, ip3, ip4)

        self.app.infoBox("wait", "plz wait console finsh")
        self.app.stop()
        multi_scan(self.ip_address_list, self.save_path)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        scan_txt(sys.argv[1])
    else:
        a = MyApp()
        a.start_app()
