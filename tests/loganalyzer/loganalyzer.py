import sys
import logging
import os
import re

from time import gmtime, strftime
from os.path import join, split
from os.path import normpath

import system_msg_handler
ANSIBLE_LOGANALYZER_MODULE = system_msg_handler.__file__.replace(r".pyc", ".py")

from system_msg_handler import AnsibleLogAnalyzer as ansible_loganalyzer
COMMON_MATCH = join(split(__file__)[0], "loganalyzer_common_match.txt")
COMMON_IGNORE = join(split(__file__)[0], "loganalyzer_common_ignore.txt")
COMMON_EXPECT = join(split(__file__)[0], "loganalyzer_common_expect.txt")
SYSLOG_TEMP_FOLDER = "/tmp/pytest-run/syslog"


class LogAnalyzer:
    def __init__(self, ansible_host, marker_prefix, run_dir="/tmp"):
        self.ansible_host = ansible_host
        self.run_dir = run_dir
        self.run_id = None
        self.extracted_syslog = os.path.join(self.run_dir, "syslog")
        self.marker_prefix = marker_prefix

        self.match_regex = []
        self.expect_regex = []
        self.ignore_regex = []

    def update_marker_prefix(self, marker_prefix):
        """
        @summary: Update configured marker prefix
        """
        self.marker_prefix = marker_prefix

    def load_common_config(self):
        """
        @summary: Load regular expressions from common files, which are localted in folder with legacy loganalyzer.
                  Loaded regular expressions are used by "analyze" method to match expected text in the downloaded log file.
        """
        analyzer = ansible_loganalyzer(self.run_id, False)
        self.match_regex = analyzer.create_msg_regex([COMMON_MATCH])[1]
        self.ignore_regex = analyzer.create_msg_regex([COMMON_IGNORE])[1]
        self.expect_regex = analyzer.create_msg_regex([COMMON_EXPECT])[1]

    def parse_regexp_file(self, src):
        """
        @summary: Get regular expressions defined in src file.
        """
        analyzer = ansible_loganalyzer(self.run_id, False)
        return analyzer.create_msg_regex([src])[1]

    def run_cmd(self, callback, *args, **kwargs):
        """
        @summary: Initialize loganalyzer, execute function and analyze syslog.

        @param callback: Python callable or function to be executed.
        @param args: Input arguments for callback function.
        @param kwargs: Input arguments for callback function.

        @return: Tuple of two items: (callback(*args, **kwargs) -> VALUE, self.analyze() -> dict)
        """
        self.init()
        try:
            call_result = callback(*args, **kwargs)
        except Exception as err:
            logging.error("Error during callback execution:\n{}".format(err))
            logging.debug("Log alaysis result\n".format(self.analyze()))
            raise err
        analysis_result = self.analyze()
        return call_result, analysis_result

    def init(self):
        """
        @summary: Add start marker into syslog on the DUT.

        @return: True for successfull execution False otherwise
        """
        logging.debug("Loganalyzer initialization...")

        self.ansible_host.copy(src=ANSIBLE_LOGANALYZER_MODULE, dest=self.run_dir)

        self.run_id = ".".join((self.marker_prefix, strftime("%Y-%m-%d-%H:%M:%S", gmtime())))
        cmd = "python {run_dir}/loganalyzer.py --action init --run_id {run_id}".format(run_dir=self.run_dir, run_id=self.run_id)

        logging.debug("Adding start marker '{}'".format(self.run_id))
        self.ansible_host.command(cmd)

    def analyze(self):
        """
        @summary: Extract syslog logs based on the start/stop markers and compose one file. Download composed file, analyze file based on defined regular expressions.

        @return: For successfull analysis phase return filled in analyzer_summary dictionary. Otherwise return empty dictionary - {}.
        """
        analyzer_summary = {"total": {"match": 0, "expected_match": 0, "expected_missing_match": 0},
                            "match_files": {},
                            "match_messages": {},
                            "expect_messages": {},
                            "unused_expected_regexp": []
                            }
        temp_folder = ".".join((SYSLOG_TEMP_FOLDER, strftime("%Y-%m-%d-%H:%M:%S", gmtime())))

        # Extract syslog files from /var/log/ and create one file by location - /tmp/syslog
        result = self.ansible_host.extract_log(directory='/var/log', file_prefix='syslog', start_string='start-LogAnalyzer-{}'.format(self.run_id), target_filename=self.extracted_syslog)

        # Download roles/test/files/tools/loganalyzer/loganalyzer.py to the DUT
        result = self.ansible_host.fetch(dest=temp_folder, src=self.extracted_syslog, flat="yes")

        analyzer = ansible_loganalyzer(self.run_id, False)
        analyzer.place_marker_to_file(temp_folder, analyzer.create_end_marker())

        match_messages_regex = re.compile('|'.join(self.match_regex)) if len(self.match_regex) else None
        ignore_messages_regex = re.compile('|'.join(self.ignore_regex)) if len(self.ignore_regex) else None
        expect_messages_regex = re.compile('|'.join(self.expect_regex)) if len(self.expect_regex) else None

        analyzer_parse_result = analyzer.analyze_file_list([temp_folder], match_messages_regex, ignore_messages_regex, expect_messages_regex)
        # Print syslog file content and remove the file
        with open(temp_folder) as fo:
            logging.debug("Syslog content:\n{}".format(fo.read()))
        os.remove(temp_folder)

        total_match_cnt = 0
        total_expect_cnt = 0
        expected_lines_total = []
        unused_regex_messages = []

        for key, value in analyzer_parse_result.iteritems():
            matching_lines, expecting_lines = value
            analyzer_summary["total"]["match"] += len(matching_lines)
            analyzer_summary["total"]["expected_match"] += len(expecting_lines)
            analyzer_summary["match_files"][key] = {"match": len(matching_lines), "expected_match": len(expecting_lines)}
            analyzer_summary["match_messages"][key] = matching_lines
            analyzer_summary["expect_messages"][key] = expecting_lines
            expected_lines_total.extend(expecting_lines)

        # Find unused regex matches
        for regex in self.expect_regex:
            for line in expected_lines_total:
                if re.search(regex, line):
                    break
            else:
                unused_regex_messages.append(regex)
        analyzer_summary["total"]["expected_missing_match"] = len(unused_regex_messages)
        analyzer_summary["unused_expected_regexp"] = unused_regex_messages

        return analyzer_summary

    def save_extracted_log(self, dest):
        """
        @summary: Download extracted syslog log file to the ansible host.

        @param dest: File path to store downloaded log file.
        """
        self.ansible_host.fetch(dest=dest, src=self.extracted_syslog, flat="yes")

