import os

def wipe_file_contents(file_path):
    try:
        with open(file_path, 'w') as file:
            file.truncate(0)
            print("Contents of", file_path, "have been wiped.")
    except FileNotFoundError:
        print("File not found at path:", file_path)

def count_lines(file_path):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            return len(lines)
    except FileNotFoundError:
        print("File not found at path:", file_path)
        return 0

if __name__ == "__main__":
    file_path = "C:\\Snort\\log\\alert.ids"
    initial_line_count = count_lines(file_path)
    wipe_file_contents(file_path)
    final_line_count = count_lines(file_path)
    print("Deleted", initial_line_count - final_line_count, "lines.")
