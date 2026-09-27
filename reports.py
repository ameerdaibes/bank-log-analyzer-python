#!/usr/bin/python3

import logging
import re
from datetime import datetime
from typing import Optional
from parser import LogEntry

def get_timestamp(entry):	#return the timestamp for entry
    return entry.TIMESTAMP

class LogAnalyzer:
    """Analyze parsed bank server log entries."""

    def __init__(self, entries, total_lines=0):
        self.entries = entries
        self.total_lines = total_lines

    def Failed_Login_Report(self):
        print("--- Failed Login Report ---")
        
        failed_entries = []
        ip_counts = {}
        user_counts = {}
        
        for entry in self.entries: #check all log entries for failed logins
            msg_upper = str(entry.MESSAGE).upper()
            if "FAILED" in msg_upper or "FAIL" in msg_upper:
                failed_entries.append(entry)
                
                ip = entry.CLIENT_IP
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
                
                user = entry.USER
                user_counts[user] = user_counts.get(user, 0) + 1

        print("Total failed login attempts: " + str(len(failed_entries)))
        
        print("\nGrouped by CLIENT_IP:") #count n print failed attempts_IP
        if len(ip_counts) == 0:
            print("None")
        else:
            for ip, count in ip_counts.items():
                print(ip + ": " + str(count) + " attempts")
                
        print("\nGrouped by USER:")	#count n print failed attempts_user
        if len(user_counts) == 0:
            print("None")
        else:
            for user, count in user_counts.items():
                print(user + ": " + str(count) + " attempts")
        
    def Query_Activity_Summary(self):
        query_counts = {
            "SELECT": 0,
            "UPDATE": 0,
            "INSERT": 0,
            "DELETE": 0
        }
        total_queries = 0

        for entry in self.entries:	# Check only QUERY log entries
            if entry.MODULE != "QUERY":
                continue

            total_queries += 1
            msg_upper = entry.MESSAGE.upper()

            for query_type in query_counts: #Count each query type
                if query_type in msg_upper:
                    query_counts[query_type] += 1
                    break
	
        print("Query Activity Summary")
        print("Total QUERY events: " + str(total_queries))
        for query_type, count in query_counts.items():
            print(query_type + ": " + str(count))

    def Slow_Query_Detector(self): #find and show slow queries
        print("\n--- Slow Query Detector ---")
        found = False
		#check warning entries
        for entry in self.entries:
            if entry.LOG_LEVEL != "WARNING":
                continue
            if "slow" not in entry.MESSAGE.lower():
                continue

            found = True
            print("User: " + str(entry.USER))
            time_match = re.search(r'took\s+([0-9.]+)\s*s', entry.MESSAGE, re.IGNORECASE) #find exec. time 
            if time_match:
                exec_time = time_match.group(1) + " s"
            else:
                exec_time = "N/A"
                
            print("Execution Time: " + exec_time)
            print("Message: " + str(entry.MESSAGE))

        if not found:
            print("No slow queries found.")

    def Transaction_Report(self): #show a basic summ of trans. activity
        print("Transaction Report")

        total_deposits = 0
        total_withdrawals = 0
        declined_count = 0
        rollback_count = 0
        
        total_deposited_amount = 0.0
        total_withdrawn_amount = 0.0

        for entry in self.entries: #check transactions summ
            if entry.MODULE != "TRANSACTION":
                continue

            msg_upper = entry.MESSAGE.upper()

            amount_match = re.search(r'([0-9]+\.[0-9]+|[0-9]+)', entry.MESSAGE) #get amount
            amount = float(amount_match.group(1)) if amount_match else 0.0

            if "DEPOSIT" in msg_upper:
                total_deposits += 1
                total_deposited_amount += amount
            elif "WITHDRAW" in msg_upper:
                total_withdrawals += 1
                total_withdrawn_amount += amount

            if "DECLINED" in msg_upper:
                declined_count += 1

            if "ROLLBACK" in msg_upper:
                rollback_count += 1
		#print the summ
        print("Total Deposits: " + str(total_deposits))
        print("Total Deposited Amount: " + str(round(total_deposited_amount, 2)))
        print("Total Withdrawals: " + str(total_withdrawals))
        print("Total Withdrawn Amount: " + str(round(total_withdrawn_amount, 2)))
        print("Declined Transactions: " + str(declined_count))
        print("Rollbacks: " + str(rollback_count))

    def Critical_Events_Report(self):
        print("Critical Events Report")

        found = False

        for entry in self.entries: # check for a critical entry
            if entry.LOG_LEVEL != "CRITICAL":
                continue

            found = True 
		#print the importaant details
            print("TIMESTAMP: " + str(entry.TIMESTAMP))
            print("MODULE: " + str(entry.MODULE))
            print("USER: " + str(entry.USER))
            print("MESSAGE: " + str(entry.MESSAGE))

        if found is False:
            print("No CRITICAL events found")

    def Login_Logout_Session_Report(self):
		# Track each session's login/logout times and calculate its duration
        print("Login/Logout Session Report")
        
        sessions = {}
        
        for entry in self.entries:
            msg_upper = str(entry.MESSAGE).upper()
            
            if "FAIL" in msg_upper or "FAILED" in msg_upper:
                continue
                
            is_login = "LOGGED IN" in msg_upper or ("LOGIN" in msg_upper and "SUCCESS" in msg_upper) or "LOGGED IN SUCCESSFULLY" in msg_upper
            is_logout = "LOGGED OUT" in msg_upper or "LOGOUT" in msg_upper
            
            if not is_login and not is_logout:
                continue
                
            if entry.SESSION_ID not in sessions:
                sessions[entry.SESSION_ID] = {
                    "user": entry.USER,
                    "login": None,
                    "logout": None
                }
            
            if is_login:
                sessions[entry.SESSION_ID]["login"] = entry.TIMESTAMP
            elif is_logout:
                sessions[entry.SESSION_ID]["logout"] = entry.TIMESTAMP

        if len(sessions) == 0:
            print("No login/logout sessions found")
            return

        for session_id, info in sessions.items():
            login_time = info["login"]
            logout_time = info["logout"]
            duration = "Not available"

            if login_time is not None and logout_time is not None:
                try:
                    login_datetime = datetime.strptime(
                        login_time,
                        "%Y-%m-%d %H:%M:%S"
                    )
                    logout_datetime = datetime.strptime(
                        logout_time,
                        "%Y-%m-%d %H:%M:%S"
                    )
                    duration = str(
                        logout_datetime - login_datetime
                    )
                except ValueError:
                    logging.warning(
                        f"Invalid timestamp format in session {session_id}"
                    )

            print("SESSION_ID: " + str(session_id))
            print("USER: " + str(info["user"]))
            
            if login_time is None:
                print("Login time: Not available")
            else:
                print("Login time: " + str(login_time))
                
            if logout_time is None:
                print("Logout time: Not available")
            else:
                print("Logout time: " + str(logout_time))
                
            if duration == "Not available":
                print("Duration: No duration time")
            else:
                print("Duration: " + str(duration))
                
            print("-" * 30)           
      
    def Events_per_Hour_Report(self):
        events_per_hour = {}
		#Count events for each hour
        for entry in self.entries:
            if len(entry.TIMESTAMP) >= 13:
                hour = entry.TIMESTAMP[11:13]
                events_per_hour[hour] = events_per_hour.get(hour, 0) + 1

        print("Events-per-Hour Report")
		#Check if there are no events
        if len(events_per_hour) == 0:
            print("No events found")
            return

        peak_hour = ""
        peak_count = -1

        for hour in sorted(events_per_hour):
            count = events_per_hour[hour]
            print(hour + ":00 - " + str(count) + " events")

            if count > peak_count:
                peak_count = count
                peak_hour = hour

        print("Peak usage hour: " + peak_hour + ":00")

    def User_Activity_Report(self, username):
        print(f"\n--- User Activity Report for: {username} ---")
        
        user_entries = []

            #Find all entries for the given user
        for entry in self.entries:
            if str(entry.USER).strip().lower() == str(username).strip().lower():
                user_entries.append(entry)

	    #Check if the user was found
        if not user_entries:
            print(f"No activity found for user '{username}'.")
            logging.warning(f"User '{username}' not found in logs.")
            return
	    #sort by time
        user_entries.sort(key=get_timestamp)

        for entry in user_entries:
            print(f"[{entry.TIMESTAMP}] [{entry.LOG_LEVEL}] [{entry.MODULE}] - {entry.MESSAGE}")

    def General_Log_Summary(self):	#general summ 
        level_counts = {
            "INFO": 0,
            "WARNING": 0,
            "ERROR": 0,
            "CRITICAL": 0
        }

        module_counts = {}
		#count log lvls and modules
        for entry in self.entries:
            if entry.LOG_LEVEL in level_counts:
                level_counts[entry.LOG_LEVEL] += 1

            module_counts[entry.MODULE] = module_counts.get(entry.MODULE, 0) + 1
		#find the busiest module
        busiest_module = "None"
        busiest_count = -1

        for module, count in module_counts.items():
            if count > busiest_count:
                busiest_module = module
                busiest_count = count

        print("General Log Summary")
        print("Total number of lines: " + str(self.total_lines))

        for log_level, count in level_counts.items():
            print(log_level + ": " + str(count))

        print("Busiest module: " + busiest_module)
