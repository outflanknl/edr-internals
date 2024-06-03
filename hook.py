import argparse
import os
import signal
import sys

import frida


def on_message(message, data):
    print(message)


def load_script(session, filepath):
    with open(filepath, "r") as file:
        script = session.create_script(file.read())

    script.on("message", on_message)
    script.load()
    print(f"Loaded script {os.path.basename(filepath)}")


def get_process(pid=None, process_name=None):
    if pid:
        return frida.attach(pid), False

    elif process_name:
        print(f"Creating a new process for {process_name}")
        pid = frida.spawn(process_name)
        return frida.attach(pid), True


def clean_exit(session, signum, frame):
    print("Detaching session and exiting.")
    session.detach()
    sys.exit(0)


def hook(args):
    session, new_process = get_process(pid=args.pid, process_name=args.name)
    print(f"Attached to PID {args.pid}")

    load_script(session, args.script)

    if new_process:
        frida.resume(session.pid)

    signal.signal(signal.SIGINT, lambda s, f: clean_exit(session, s, f))
    print("Press Ctrl+C to stop tracing...")
    signal.pause()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Load Frida scripts into a process and attach to it."
    )
    parser.add_argument("-p", "--pid", type=int, help="Process ID to attach to")
    parser.add_argument(
        "-n", "--name", type=str, help="Name of the process to spawn and attach to"
    )
    parser.add_argument(
        "-s",
        "--script",
        type=str,
        required=True,
        help="Path to the Frida script to load",
    )

    args = parser.parse_args()

    if not args.pid and not args.name:
        raise ValueError("No PID or process name provided")

    hook(args)
