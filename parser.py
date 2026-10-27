import re

def extract_ip(line):
    # Regular expression pattern to match IP addresses
    pattern = r"\d+\.\d+\.\d+\.\d+"

    match = re.search(pattern, line)

    if match:
        return match.group()

    return None


def extract_username(line):
    # Regular expression pattern to match usernames
    words = line.split()

    if "from" in words:
        from_index = words.index("from")
        return words[from_index - 1]  # Return the word before "from"

    return None

def extract_timestamp(line):
    # Regular expression pattern to match timestamps
        words = line.split()

        return f"{words[0]} {words[1]} {words[2]}"  # Return the first three words as timestamp
   


def parse_log_entry(line):
    # Regular expression pattern to match log entry components
    entry = {
        "ip": extract_ip(line),
        "status": "Failed" if "Failed" in line else "Accepted",
        "username": extract_username(line),
        "timestamp": extract_timestamp(line)
    }

    return entry


def read_log_file(file_path):
    parsed_logs = []

    #read log file
    with open(file_path, 'r') as logfile:
        for line in logfile:
            print("Reading", line)
            
            entry = parse_log_entry(line)
            parsed_logs.append(entry)
            

    return parsed_logs





