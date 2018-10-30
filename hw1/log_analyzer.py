#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import argparse
import configparser
from glob import glob
import gzip
from pprint import pprint
import itertools
from string import Template
from json import dumps
from datetime import datetime
from collections import namedtuple
import logging
from copy import copy


# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';


config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log"
}


def get_script_path():
    return os.path.dirname(__file__)


def get_cmd_args():
    """
    Comment
    """
    parser = argparse.ArgumentParser(description='Log analyzer')
    parser.add_argument('--config', default="default.ini", help='custom config file')
    
    return parser.parse_args()


def get_config(config_filename, default_config):
    """
    Возвращает смерженный конфиг

    :param cmd_args:
    :param default_config:
    :return: dict
    """
    result_config = copy(default_config)
    config_filename = os.path.join(get_script_path(), config_filename)

    if not os.path.exists(config_filename):
        raise Exception("Config file \"{}\" was not found".format(config_filename))

    config = configparser.ConfigParser()
    config.read(config_filename)

    default = config['default']
    for key in default.keys():
        result_config[key.upper()] = default.get(key)

    return result_config


def check_exists(func):
    """
    Декоратор проверяющий наличие папки/файла и если нету — генерит исключение

    :param func:
    :return:
    """
    def wrapper(*args, **kwargs):
        path = func(*args, **kwargs)

        if os.path.exists(path):
            return path

        raise Exception("\"{}\" does not exists".format(path))

    return wrapper


@check_exists
def relpath(path):
    """
    Вычисляет относительный путь (декоратор проверяет есть ли он)

    :param path: str
    :return: str
    """
    return os.path.abspath(os.path.join(get_script_path(), *path.split(os.path.sep)))


def get_logfile_for_analyze(log_dir, report_dir):
    """
    Берет последний лог из папки log_dir по дате в имени файла,
    проверяет есть ли соответствующий отчет в папке report_dir

    :param log_dir: str
    :param report_dir: str
    :return: str|Exception
    """
    LogFile = namedtuple("LogFile", ['filename', 'date'])

    suffix = 'nginx-access-ui.log-'
    supported_exts = [None, 'gz']

    def get_date_from_filename(filename):
        parts = filename.split(suffix)
        date_str = parts[-1].split(".")[0]

        return datetime.strptime(date_str, '%Y%m%d').date()

    def get_log_ext(filename):
        parts = filename.split(suffix)
        if parts[-1].isdigit():
            return None

        return parts[-1].split(".").pop()

    # да, тут сделано через glob, я так умею
    # видимо надо было читать директорию и там уже была бы сортировка лексикографическа
    files = glob(os.path.abspath(os.path.join(log_dir, "{}*".format(suffix))))
    files = [filename for filename in files if get_log_ext(filename) in supported_exts]

    if files:
        files = sorted(files, reverse=True, key=lambda filename: get_date_from_filename(filename))
        log_file = LogFile(files[0], get_date_from_filename(files[0]))

        report_filename = get_report_filename(report_dir, log_file.date.strftime("%Y.%m.%d"))
        if not os.path.exists(report_filename):
            return log_file

        raise Exception("Last logfile '{}' already processed, see report at '{}'".format(
            log_file.filename,
            report_filename
        ))

    raise Exception("No logs was found in {} for process".format(log_dir))


def parse_log_line(line):
    """
    Парсит строку лога (из задания и проверяет на общую корректность)

    :param line:
    :return: list
    """
    def _parse_log_line():
        """
        Внутренний генератор который перебирает символы и "выплевывает" распаршенные кусочки

        :return: generator
        """
        quote_opened = False
        square_opened = False
        buffer = ""

        for symbol in line:
            if symbol == '"':
                quote_opened = not quote_opened
            elif symbol == '[':
                square_opened = True
            elif symbol == ']':
                square_opened = False
            elif symbol == ' ':
                if quote_opened or square_opened:
                    buffer += symbol
                elif buffer:
                    yield buffer
                    buffer = ""
                else:
                    pass
            else:
                buffer += symbol
        if buffer:
            yield buffer

    def parse_datetime(raw):
        """
        not implemented

        :param raw: str
        :return: str?
        """
        return raw

    def parse_http_request(raw):
        available_http_methods = ['GET', 'POST', 'PUT']
        ret = raw.split()

        if len(ret) != 3 or \
                ret[0] not in available_http_methods or \
                not ret[2].startswith('HTTP'):
            raise Exception("Invalid HTTP Request format '{}'".format(raw))

        return ret

    def parse_int(raw):
        return int(raw)

    def parse_float(raw):
        return float(raw)

    functions = {
        3: parse_datetime,
        4: parse_http_request,
        5: parse_int,
        6: parse_int,
        12: parse_float
    }

    ret = list(_parse_log_line())
    if len(ret) != 13:
        raise Exception("Invalid log line '{}".format(line))

    for key, value in enumerate(ret):
        if key in functions:
            try:
                ret[key] = functions[key](value)
            except Exception as e:
                logging.debug("Parsing error at line: '{}'".format(line))
                logging.exception(e)
                raise e

    return ret


def percentile(data: list, level: float):
    """
    Перцентиль

    :param data:
    :param level:
    :return:
    """
    if len(data) == 1:
        return data[0]

    if level > 1:
        raise Exception("Invalid percentile: '{}'".format(percentile))

    length = len(data)
    index = (length - 1.) * level

    data = sorted(data)

    if index.is_integer():
        return data[int(index)]
    else:
        return (data[int(index)] + data[int(index) + 1]) / 2


def median(data):
    """
    Медиана

    :param data:
    :return:
    """
    return percentile(data, 0.5)


def get_report_filename(report_dir, date_str):
    return os.path.join(report_dir, "report-{}.html".format(date_str))


def parse_log_file(filename, debug=None, threshold=50):
    """
    Парсит лог-файл, возвращает статистику по нему, проверяет на предельное количество ошибок

    :param filename:
    :param debug:
    :param thesh:
    :return:
    """
    stats = {}

    open_function = gzip.open if filename.endswith(".gz") else open
    open_mode = "rt" if filename.endswith(".gz") else "r"

    lines_was_read = 0
    lines_with_errors = 0
    with open_function(filename, open_mode) as fp:
        for line in fp:
            line = line.strip()
            try:
                parsed_log_line = list(parse_log_line(line))

                url = parsed_log_line[4][1]
                request_time = parsed_log_line[-1]
                stats.setdefault(url, []).append(request_time)
            except Exception:
                lines_with_errors += 1
                logging.exception("Could not parse line: '{}'".format(line))
            finally:
                lines_was_read += 1

                if debug and lines_was_read >= debug:
                    break

    if lines_with_errors / lines_was_read * 100 >= threshold:
        raise Exception("Too many errors in '{}'".format(filename))

    return stats


def calculate_stats(stats: list, report_size):
    # all_requests_times = list(itertools.chain(*[value for value in stats.values()]))
    all_requests_times = list(itertools.chain(*stats.values()))
    summary_requests_time = sum(all_requests_times)
    summary_requests_count = len(all_requests_times)

    stats_sorted = sorted(stats.items(), key=lambda item: sum(item[1]), reverse=True)

    calculated_stats = []
    report_size_counter = 0
    for url, values in stats_sorted:
        count = len(values)
        count_perc = count / summary_requests_count * 100

        time_sum = sum(values)
        time_perc = time_sum / summary_requests_time * 100

        time_avg = time_sum / count
        time_max = max(values)
        time_med = median(values)

        calculated_stats.append({
            'url': url,
            'count': count,
            'count_perc': count_perc,
            'time_sum': time_sum,
            'time_perc': time_perc,
            'time_avg': time_avg,
            'time_max': time_max,
            'time_med': time_med
        })

        report_size_counter += 1
        if report_size_counter >= report_size:
            break

    return calculated_stats


def get_report_template_filename():
    return os.path.join(get_script_path(), "report_template.html")


def main(*, default_config, debug=True):
    """
    Точка входа программы

    :param default_config:
    :param debug:
    :return:
    """
    stats = {}
    try:
        cmd_args = get_cmd_args()
        config = get_config(cmd_args.config, default_config)

        log_dir, report_dir, report_size = relpath(config.get('LOG_DIR')), relpath(config.get('REPORT_DIR')), int(config.get('REPORT_SIZE'))

        logging.basicConfig(filename=config.get('LOGGING_FILENAME', None),
                            level=logging.DEBUG if debug else logging.INFO,
                            format="[%(asctime)s] %(levelname).1s %(message)s",
                            datefmt="%Y.%m.%d %H:%M:%S")

        logging.info("Log analyzer started in " + ("production" if not debug else "debug") + " mode")
        logging.debug("CMD args: [" + ", ".join(["'{}'".format(arg) for arg in sys.argv]) + "]")
        logging.info("Config: log_dir='{}', report_dir='{}', report_size='{}'".format(log_dir, report_dir, report_size))

        log_file = get_logfile_for_analyze(log_dir, report_dir)
        logging.info("Choosed log file: '{}'".format(log_file.filename))

        stats = parse_log_file(log_file.filename, 1000 * 1000 if debug else None)
        calculated_stats = calculate_stats(stats, report_size)

        report_filename = get_report_filename(report_dir, log_file.date.strftime("%Y.%m.%d"))
        with open(get_report_template_filename(), 'r') as template_fp:
            template = Template(template_fp.read())

            with open(report_filename, 'w') as report_fp:
                report_fp.write(template.safe_substitute(table_json=dumps(calculated_stats)))

    except Exception as e:
        logging.exception("Exception occured:")
        print(e, file=sys.stderr)
        return 1

    print("Enjoy result at '{}'".format(report_filename))
    print("Bye!")
    return 0


if __name__ == "__main__":
    sys.exit(main(default_config=config, debug=not True))


