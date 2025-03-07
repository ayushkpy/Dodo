import subprocess

def run_python_script(script_name):
    """Function to run a Python script using subprocess.Popen."""
    process = subprocess.Popen(["python3", script_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return process

def main():
    # Python scripts to run
    script1 = "bot.py"  # First Python script
    script2 = "proxies.py"  # Second Python script

    # Start both scripts
    print(f"Starting {script1}...")
    process1 = run_python_script(script1)
    print(f"Starting {script2}...")
    process2 = run_python_script(script2)

    # Wait for both processes to complete
    print("Waiting for processes to finish...")
    stdout1, stderr1 = process1.communicate()  # Wait for process1 to finish
    stdout2, stderr2 = process2.communicate()  # Wait for process2 to finish

    # Print outputs and errors (if any)
    print(f"Output of {script1}:\n{stdout1.decode()}")
    if stderr1:
        print(f"Errors from {script1}:\n{stderr1.decode()}")

    print(f"Output of {script2}:\n{stdout2.decode()}")
    if stderr2:
        print(f"Errors from {script2}:\n{stderr2.decode()}")

    print("Both processes have finished.")

if __name__ == "__main__":
    main()