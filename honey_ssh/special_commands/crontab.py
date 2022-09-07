

def special_command(args):
    command_string, client_info, logging_client = pop_default_args(args)
    return "no crontab for " + client_info.username + "\r\n"


def pop_default_args(args):
    return args[0], args[1], args[2]
