import subprocess
import json

def run_nuclei_scan(target: str) -> str:
    """
    Runs the 'nuclei' command on a single target and returns the
    raw JSON string output.
    
    Raises:
        subprocess.CalledProcessError: If Nuclei fails.
        FileNotFoundError: If Nuclei is not installed.
    """
    
    # We use -json to get machine-readable output
    # We use -silent to hide the startup banner
    command = ["nuclei", "-u", target, "-json", "-silent"]
    
    print(f"Running command: {' '.join(command)}") # For debugging

    # This runs the command and waits for it to finish
    result = subprocess.run(
        command,
        capture_output=True,  # Grab stdout and stderr
        text=True,            # Decode output as a string (not bytes)
        check=True            # Raise an error if the command fails
    )
    
    # result.stdout contains all the text output from the command
    return result.stdout