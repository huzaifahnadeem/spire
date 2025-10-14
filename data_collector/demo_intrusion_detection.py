import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

buffer = []

NEW_ENTRY = '# === New Entry ==='
END_ENTRY = '# === End Entry ==='

def main():
    path_to_watch = "."  # Monitor the current directory
    file_to_watch = "log_file.yaml"
    
    event_handler = MyLogHandler(f"{path_to_watch}/{file_to_watch}")
    observer = Observer()
    observer.schedule(event_handler, path_to_watch, recursive=False)
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()

def parse_logic(line):
    # there is an empty line following END_ENTRY and before the start of NEW_ENTRY
    if (line == '' and (buffer[-1] == '' and buffer[-2] == END_ENTRY) and (buffer[0] == NEW_ENTRY)): # ensure that the buffer only contains one entry # TODO: this may be incorrect as we may have a potential backlog of unprocessed entried?
        pass
    else:
        buffer.append()

class MyLogHandler(FileSystemEventHandler):
    """A custom event handler to process log file changes."""
    def __init__(self, filepath):
        self.filepath = filepath
        # Store the current position to start reading from.
        self.file_pos = 0
        self._check_file_on_start()

    def _check_file_on_start(self):
        """Initial check to handle file content that existed before monitoring started."""
        try:
            with open(self.filepath, 'r') as f:
                f.seek(0, 2)  # Go to the end
                self.file_pos = f.tell()
        except FileNotFoundError:
            print(f"Warning: File not found: {self.filepath}. Waiting for it to be created.")
            self.file_pos = 0

    def on_modified(self, event):
        """Called when a file is modified."""
        if not event.is_directory and event.src_path == self.filepath:
            self.read_new_content()

    def read_new_content(self):
        """Reads and processes new lines from the file."""
        try:
            with open(self.filepath, 'r') as f:
                f.seek(self.file_pos)
                new_lines = f.readlines()
                for line in new_lines:
                    print(f"New line detected: {line.strip()}")
                    parse_logic(line)
                    
                
                # Update the file position after processing
                self.file_pos = f.tell()

        except FileNotFoundError:
            self.file_pos = 0
        except Exception as e:
            print(f"Error reading file: {e}")

if __name__ == "__main__":
    main()
