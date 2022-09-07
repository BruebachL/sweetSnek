import random
from datetime import datetime


def special_command(args):
    command_string, client_info, logging_client = pop_default_args(args)
    return datetime.now().strftime("%H:%M:%S") + " up " + str(
        random.randrange(10, 59)) + " min,  0 users,  load average: 0." + str(random.randrange(10, 99)) + ", 0." + str(
        random.randrange(10, 99)) + ", 0." + str(random.randrange(10, 99)) + "\r\n" + \
           "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT" + "\r\n"


def pop_default_args(args):
    return args[0], args[1], args[2]
