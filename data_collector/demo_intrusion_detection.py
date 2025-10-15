import sys, os
import yaml
import threading
from queue import Queue
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

TIME_DELTA_OK = 2   # in seconds
NEW_ENTRY = '# === New Entry ===\n'
END_ENTRY = '# === End Entry ===\n'

entries_all_queues = {}
not_yet_matched_entries = {} # key= filenames. val= list of tuple: (timestamp, entry)

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "./data_collector_logs"
    
    event_handler = myHandler(path)
    observer = Observer()
    observer.schedule(event_handler, path, recursive=False)
    observer.start()

    data_proc_thr = threading.Thread(target=process_entries)
    data_proc_thr.start()

    try:
        while observer.is_alive():
            observer.join(1)
    finally:
        observer.stop()
        observer.join()
    
    data_proc_thr.join()

def process_entries():
    while True:
        try:
            entries_all_queues_keys = [k for k in entries_all_queues.keys()] # due to threading we can get 'RuntimeError: dictionary changed size during iteration' error. so cant use entries_all_queues.keys() directly in the following for loop
            for filename in entries_all_queues_keys:
                if "hmi_" in filename: # ignore hmi data file.. not processing that for now
                    continue

                q = entries_all_queues[filename]
                entry: dict = q.get()
                curr_time = list(entry.keys())[0] # each entry has a root key which is its timestamp in unix time in microsec

                # entry processing logic:
                # see if there is something in the not_yet_matched_entries for other files (that list contains entries that have not been matched between the data files yet)
                # if all the lists of the other files are empty, put this entry there with extra data. that list stores tuple: (timestamp, entry)
                # if non empty, go through all entries and do the following:
                #   1) check each entry's timestamp and it current timestamp - that timetamp > TIME_DELTA_OK, alert
                #   2) if find matching entry within delta, delete the one already in the list and throw this one away TODO: this will only work if we only have two system instances only
                
                for f in entries_all_queues_keys:
                    if f not in list(not_yet_matched_entries.keys()):
                        not_yet_matched_entries[f] = []
                    if f == filename: # dont go through this files own entries -- need to compare to other files' entries
                        continue
                    
                    found_a_matching_entry = False
                    for i, (this_ts, this_entry) in enumerate(not_yet_matched_entries[f]):
                        pop_indices = []
                        if entries_are_same(entry, this_entry):
                            found_a_matching_entry = True
                            pop_indices.append(i)
                            if (abs((this_ts - curr_time)/1000000) < TIME_DELTA_OK): # divide by 1000000 to convert microsec to seconds
                                print(f"Matching entry within TIME_DELTA_OK between {f} and {filename}")
                            else:
                                print(f"ALERT: TIME_DELTA_OK exceeded for an entry between {f} and {filename}")
                        for i in pop_indices: # remove the matching entries
                            not_yet_matched_entries[f].pop(i)
                    
                    if not found_a_matching_entry: # then put it in your own list
                        not_yet_matched_entries[filename].append((curr_time, entry))

                q.task_done()
        except Exception as e:
            print(e)

def entries_are_same(entry1, entry2) -> bool:
    are_same = True
    return are_same

class fileTracker:
    def __init__(self):
        self.pos = 0        # init all file_pos to 0
        self.buffer = []    # this will contain all the lines that still need to be processed. init to empty list

class myHandler(FileSystemEventHandler):
    """A custom event handler to process log file changes."""
    def __init__(self, dirpath):
        self.dirpath = dirpath
        self.files = {} # keys: names of all the files in self.dirpath. vals: fileTracker (which has the final position read from in the file & the buffer of lines that need to be processed still for this file)
        all_files = self._find_all_files()
        for f in all_files:
            self.files[f] = fileTracker()
            entries_all_queues[f] = Queue()
        self._check_files_on_start()

    def _find_all_files(self):
        """
        Finds and returns a list of all files in a given directory and its subdirectories.
        """
        directory = self.dirpath
        file_paths = []
        for root, _, files in os.walk(directory):
            for file in files:
                file_paths.append(os.path.join(root, file))
        return file_paths
    
    def _check_files_on_start(self):
        """Initial check to handle file content that existed before monitoring started."""
        for this_file_path in self.files.keys():
            try:
                with open(this_file_path, 'r') as f:
                    f.seek(0, 2)  # Go to the end
                    self.files[this_file_path].pos = f.tell()
            except FileNotFoundError:
                print(f"Warning: File not found: {this_file_path}.")

    def on_created(self, event):
        """Called when a file or directory is created."""
        if not event.is_directory: # on_created is called for both new files and new directories. we only expect to have new files and not directories created in our dirpath so just a check to avoid any errors if there is a dir created somehow
            newly_created_file = event.src_path # just keep track of this new file too
            self.files[newly_created_file] = fileTracker()
            entries_all_queues[newly_created_file] = Queue()

    def on_modified(self, event):
        """Called when a file is modified."""
        if (not event.is_directory):
            if (event.src_path not in self.files.keys()):
                raise ValueError(f'on_modified was called for `{event.src_path}` which is not in our self.files')
            
            self.read_new_content(event.src_path)

    def read_new_content(self, file_name):
        """Reads and processes new lines from the file."""
        try:
            with open(file_name, 'r') as f:
                f.seek(self.files[file_name].pos)
                new_lines = f.readlines()
                for line in new_lines:
                    # print(f"New line detected in {file_name}: {line.strip()}")
                    self.parse_logic(file_name, line)
                    
                # Update the file position after processing
                self.files[file_name].pos = f.tell()

        except Exception as e:
            print(f"Error reading file: {e}")
    
    def parse_logic(self, file_name, line):
        # each log file is a yaml file. we need to wait for each entry to be written to before processing it. data collector writes to the file line by line. So, if we try to process it while an entry is incomplete, it may not be a valid yaml file
        # so. we see if the line represents an end of entry and process it if so. Otherwise, we put it in the buffer and process it later when we get to its END_ENTRY marker

        # there is an empty line following END_ENTRY and before the start of NEW_ENTRY
        # we do not have to keep an empty line in the buffer so ignore if so:
        if "hmi_" in file_name:
            return
        
        if (line.strip() == ''):
            return

        this_line = line
        # store the line at the end of the buffer
        self.files[file_name].buffer.append(this_line)

        if (this_line == END_ENTRY):
            # find the previous NEW_ENTRY and process this entry
            for i in range(-1, -1*len(self.files[file_name].buffer), -1): # reverse loop
                buff_line = self.files[file_name].buffer[i]
                if buff_line == NEW_ENTRY:
                    break

            entry_lines = self.files[file_name].buffer[i-1:]
            entry_string = "".join(entry_lines)
            del self.files[file_name].buffer[i-1:]
            yaml_data = yaml.safe_load(entry_string)
            entries_all_queues[file_name].put(yaml_data)

if __name__ == "__main__":
    main()
