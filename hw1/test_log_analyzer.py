import unittest

from log_analyzer import *
from collections import namedtuple
from datetime import datetime


class LogAnalyzerTest(unittest.TestCase):

    def test_get_config(self):
        """
        Тесты функции чтения и мерджа конфига
        """
        config = {
            "REPORT_SIZE": 100,
            "LOG_DIR": "./log"
        }

        result_config = get_config("default.ini", config)

        self.assertEqual(result_config['REPORT_SIZE'], '1000')
        self.assertEqual(result_config['REPORT_DIR'], './reports')
        self.assertEqual(result_config['LOG_DIR'], './log')
        self.assertEqual(result_config['LOGGGER_FILENAME'], './log_analyzer.log')

    def test_parse_log_line(self):
        line = '1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300] "GET /api/v2/banner/25019354 HTTP/1.1" 200 927 "-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697422-2190034393-4708-9752759" "dc7161be3" 0.390'
        parsed = parse_log_line(line)

        self.assertEqual(parsed[4][0], "GET")
        self.assertEqual(parsed[-1], 0.390)

        failed = False
        try:
            line = """1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300] "FET /api/v2/banner/25019354 HTTP/1.1" 200 927 "-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697422-2190034393-4708-9752759" "dc7161be3" 0.390"""
            parsed = parse_log_line(line)
        except Exception:
            failed = True
        finally:
            self.assertEqual(failed, True)

        failed = False
        try:
            line = """1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300] "GET /api/v2/banner/25019354 FTP/1.1" 200 927 "-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697422-2190034393-4708-9752759" "dc7161be3" 0.390"""
            parsed = parse_log_line(line)
        except Exception:
            failed = True
        finally:
            self.assertEqual(failed, True)

        failed = False
        try:
            line = """1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300] "GET /api/v2/banner/25019354 FTP/1.1" dvesti 927 "-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697422-2190034393-4708-9752759" "dc7161be3" 0.390"""
            parsed = parse_log_line(line)
        except Exception as e:
            failed = True
        finally:
            self.assertEqual(failed, True)

    def test_get_report_filename(self):
        self.assertEqual(get_report_filename("/tmp", '2018.01.01'), '/tmp/report-2018.01.01.html')

    def test_median(self):
        self.assertEqual(median([1, 1, 1, 1, 5]), 1)

    def test_percentile(self):
        self.assertEqual(percentile(list(range(10)), 0.9), 8.5)
        self.assertEqual(percentile(list(range(10)), 0.8), 7.5)

    def testFileParser(self):
        pass


if __name__ == '__main__':
    unittest.main()
