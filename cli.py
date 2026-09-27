#!/usr/bin/python3

import logging
from parser import parse_log_file
from reports import LogAnalyzer

def run_program():
		#ask for the log file name from user
    while True:
        file_name = input("Enter log file name (bank_server.log was used in our project) :").strip() or "bank_server.log"
        try:
            entries, total = parse_log_file(file_name)
            break
        except FileNotFoundError:
            print(f"Error: File '{file_name}' not found. Please try again.")
            logging.error("Log file not found")

    analyzer = LogAnalyzer(entries, total)	#create anal. obj.
		#menu
    while True:
        print("\n--- Bank Log Analyzer ---")
        print("1. Failed Login Report")
        print("2. Query Activity Summary")
        print("3. Slow Query Detector")
        print("4. Transaction Report")
        print("5. Critical Events Report")
        print("6. User Activity Report")
        print("7. Login/Logout Session Report")
        print("8. Events-per-Hour Report")
        print("9. General Log Summary")
        print("0. Exit")

        choice = input("Enter choice (0-9): ").strip()

        if choice == "0":
            print("Goodbye!")
            break
        elif choice == "1":
            analyzer.Failed_Login_Report()
        elif choice == "2":
            analyzer.Query_Activity_Summary()
        elif choice == "3":
            analyzer.Slow_Query_Detector()
        elif choice == "4":
            analyzer.Transaction_Report()
        elif choice == "5":
            analyzer.Critical_Events_Report()
        elif choice == "6":
            user = input("Enter username: ").strip()	#ask for a certain user
            analyzer.User_Activity_Report(user)
        elif choice == "7":
            analyzer.Login_Logout_Session_Report()
        elif choice == "8":
            analyzer.Events_per_Hour_Report()
        elif choice == "9":
            analyzer.General_Log_Summary()
        else:
            print("Invalid choice, try again.")
            logging.warning("Invalid menu choice entered")

if __name__ == "__main__":
    run_program()
