'''
Created on Mar 24, 2016

@author: weidenba
'''
import unittest
from os import path

from common_analysis_oms.oms import CommonAnalysisOMS

BASE_DIR = path.dirname(path.abspath(__file__))
BENIGN_FILE_PATH = path.join(BASE_DIR, "data/benign")
MALICIOUS_FILE_PATH = path.join(BASE_DIR, "data/eicar")


class Test(unittest.TestCase):

    def setUp(self):
        self.oms = CommonAnalysisOMS()

    def tearDown(self):
        pass

    def test_plugin_init(self):
        self.assertGreater(len(self.oms.av_list), 0, "no scanners installed, please install at least clamav")

    def test_get_av_scan_result(self):
        self.assertEqual(self.oms.get_av_scan_result({"command": "echo $filepath"}, "test"), "test\n")

    def test_find_malware_name(self):
        self.assertEqual(self.oms.find_malware_name("test string", {"re_malware_name": "str([\w]+)"}), "ing")

    def test_scan_benign(self):
        result = self.oms.scan_file(BENIGN_FILE_PATH)
        self.assertEqual(result["positives"], 0)
        self.assertTrue(True not in [result["scans"][av]["detected"] for av in result["scans"]])

    def test_scan_malicious(self):
        result = self.oms.scan_file(MALICIOUS_FILE_PATH)
        self.assertEqual(result["positives"], result['number_of_scanners'])
        self.assertTrue(False not in [result["scans"][av]["detected"] for av in result["scans"]])


if __name__ == "__main__":
    unittest.main()
