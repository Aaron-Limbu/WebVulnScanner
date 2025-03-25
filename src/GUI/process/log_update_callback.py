import sys
import io
import datetime
class RedirectOutput(io.StringIO):
    def __init__(self, callback,filename):
        super().__init__()
        self.callback = callback
        self.log_filename= filename

    def write(self, message):
        message = message.strip()
        if message:
            #since the logs were not being created or written as i thought it would
            with open(self.log_filename, "a") as log_file:
                log_file.write(f"{datetime.datetime.now().strftime("%c")} - {message}\n") #manually writing logs
            self.callback(message + "\n")  # Update the UI with new messages
        super().write(message)  # Optionally keep the message in memory

    def flush(self):
        sys.__stdout__.flush()  # Ensure stdout gets flushed
        sys.__stderr__.flush()  # Ensure stderr gets flushed
