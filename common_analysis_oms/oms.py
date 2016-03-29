# -*- coding: utf-8 -*-
from common_analysis_base import AnalysisPluginFile
from common_helper_files import get_directory_for_filename, get_version_string_from_git

import hashlib
import json
from re import findall
from subprocess import Popen, PIPE
from os import listdir, path
from distutils import spawn
import logging

plugin_version = get_version_string_from_git(get_directory_for_filename(__file__))
system_version = "OMS 0.2.1"


class CommonAnalysisOMS(AnalysisPluginFile):
    """
    The OMS plugin scans a file with several malware scanners.

    :iconst av_list: List of installed malware scanners
    """

    av_list = []
    BASE_DIR = path.dirname(path.abspath(__file__))
    PLUGIN_DIR = path.join(BASE_DIR, "plugins")

    def __init__(self):
        super(CommonAnalysisOMS, self).__init__(plugin_version, system_version=system_version)
        self.load_plugins()
        self.result_dict = {}

    def analyze_file(self, file_path):
        self.result_dict = self.prepare_analysis_report_dictionary()
        self.scan_file(file_path)
        return self.result_dict

    def get_av_scan_result(self, av, filepath):
        scanprocess = Popen(av["command"].replace("$filepath", filepath), shell=True, stdout=PIPE)
        scanresult = scanprocess.stdout.read().decode("utf-8", errors='ignore')
        logging.debug(scanresult)
        return scanresult

    @staticmethod
    def find_malware_name(scanresult, av):
        try:
            return ", ".join(findall(av["re_malware_name"], scanresult))
        except IndexError:
            # if the result is empty, there is an error with the RE
            logging.error("error with malware name regular" + "expression for {}".format(av["name"]))
            return ""

    def parse_scan_result(self, scanresult, av):
        infection_indicator = findall(av["re_infected"], scanresult)
        logging.debug("indicator: {}".format(infection_indicator))
        # if there is an infected file:
        if infection_indicator not in [["0"], []]:
            finding = self.find_malware_name(scanresult, av)
            self.result_dict["positives"] += 1
        else:
            finding = "clean"
        print("result: " + finding)
        return {"result": finding,
                "detected": finding != "clean",
                "version": self.get_av_scan_result(av, "--version")}

    def remove_not_installed_avs(self):
        for av in self.av_list[:]:
            program = av["command"].split(" ")[0]
            if not spawn.find_executable(program):
                self.av_list.remove(av)

    def execute_scans(self, filepath):
        result = {}
        for av in self.av_list:
            print("Starting scan with {} ({}/{})".format(av["name"],
                  self.av_list.index(av) + 1, self.result_dict["number_of_scanners"]))
            scanresult = self.get_av_scan_result(av, repr(path.abspath(filepath)))
            logging.debug(repr(scanresult))
            result[av["name"]] = self.parse_scan_result(scanresult, av)
        return result

    def load_plugins(self):
        self.av_list = []
        plugin_files = [f for f in listdir(self.PLUGIN_DIR)
                        if f[-4:] == "json"]
        for f in plugin_files:
            with open(path.join(self.PLUGIN_DIR, f), "r") as fp:
                self.av_list.append(json.load(fp))
        self.remove_not_installed_avs()

    @staticmethod
    def load_file_content(filepath):
        with open(filepath, "rb") as fp:
            return fp.read()

    def get_md5(self, filepath):
        m = hashlib.md5()
        m.update(self.load_file_content(filepath))
        return m.hexdigest()

    def scan_file(self, file_to_analyze):
        self.result_dict
        self.result_dict["positives"] = 0
        self.result_dict["md5"] = self.get_md5(file_to_analyze)
        self.result_dict["scanners"] = [av["name"] for av in self.av_list]
        self.result_dict["number_of_scanners"] = len(self.result_dict["scanners"])
        self.result_dict["scans"] = self.execute_scans(file_to_analyze)
        logging.debug(self.result_dict)
        return self.result_dict
