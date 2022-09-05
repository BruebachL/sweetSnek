import importlib


def populate_known_special_commands():
    special_commands = {}
    from os import listdir
    from os.path import isfile, join
    onlyfiles = [f.replace(".py", '') for f in listdir("./special_commands") if isfile(join("./special_commands/", f))]
    for file in onlyfiles:
        print(file)
        try:
            mymodule = importlib.import_module('special_commands.' + file)
            special_commands[file] = mymodule

        except Exception as e:
            import traceback
            traceback.print_exc()
    return special_commands


class SpecialCommandHandler:

    def __init__(self):
        self.known_special_commands = populate_known_special_commands()
