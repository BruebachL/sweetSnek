def parse_config(filepath):
    config = {}
    with open(filepath) as file:
        lines = [line.strip('\n').replace('\\n', '\n').replace('\\r', '\r') for line in file.readlines()]
        current_header = ""
        for line in lines:
            if line[0] == '[' and line[-1] == ']':
                current_header = line.removeprefix('[').removesuffix(']')
            else:
                if current_header in config:
                    config[current_header].append(line)
                else:
                    config[current_header] = [line]

    return config


class PluginConfiguration:

    def __init__(self, filepath):
        self.config = parse_config(filepath)
