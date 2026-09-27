#!/usr/bin/python3

#parser for the bank server log file

import logging
import re
	
LOG_PATTERN = re.compile(		#to read every part of the log line
    r'^\[(?P<TIMESTAMP>[^\]]+)\]\s+'
    r'\[(?P<LOG_LEVEL>[^\]]+)\]\s+'
    r'\[(?P<SESSION_ID>[^\]]+)\]\s+'
    r'\[(?P<USER>[^\]]+)\]\s+'
    r'\[(?P<CLIENT_IP>[^\]]+)\]\s+'
    r'\[(?P<MODULE>[^\]]+)\]\s+-\s+'
    r'(?P<MESSAGE>.*)$'
)

class LogEntry:	#store one log entry
    def __init__(self, TIMESTAMP, LOG_LEVEL, SESSION_ID, USER, CLIENT_IP, MODULE, MESSAGE):
        self.TIMESTAMP = TIMESTAMP
        self.LOG_LEVEL = LOG_LEVEL
        self.SESSION_ID = SESSION_ID
        self.USER = USER
        self.CLIENT_IP = CLIENT_IP
        self.MODULE = MODULE
        self.MESSAGE = MESSAGE

def parse_log_file(file_name):	#read and parse
    entries = []
    total_lines = 0
    
    try:	#open the file and read every line,, line by line
        with open(file_name, "r", encoding="utf-8-sig") as f:
            for line in f:
                total_lines += 1
                cleaned_line = line.strip()
                if not cleaned_line:	#skip empty lines
                    continue
                    
                match = LOG_PATTERN.match(cleaned_line)	#match the line with the pattern
                
                if match:	#create an object from thr matched info
                    entry = LogEntry(**match.groupdict())
                    entries.append(entry)
                else:
                    logging.warning(f"Invalid log line {total_lines} skipped")
    except FileNotFoundError:
        logging.error(f"Log file '{file_name}' not found during parsing.")
        raise
                
    return entries, total_lines
