"""One-shot adapter launcher with hard CPU/output limits and no shell."""

import math
import os
import resource
import sys


def main():
    output, seconds = int(sys.argv[1]), math.ceil(float(sys.argv[2])) + 1
    resource.setrlimit(resource.RLIMIT_FSIZE, (output, output))
    resource.setrlimit(resource.RLIMIT_CPU, (seconds, seconds))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    if sys.platform != "darwin":
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1048576, 512 * 1048576))
    command = sys.argv[3:]
    os.execv(command[0], command)


if __name__ == "__main__":
    main()
