from honey_log.plugin.plugin import Plugin
from honey_log.plugin.plugin_configuration import PluginConfiguration


class PluginHandler:

    def __init__(self):
        self.plugins = parse_configs()

    def print_plugins(self):
        for plugin in self.plugins:
            print(self.plugins[plugin].name)
            print(self.plugins[plugin].plugin_chain)

    def handle_event(self, event):
        for plugin in self.plugins:
            plugin_event = event
            for plugin_in_chain in self.plugins[plugin].plugin_chain:
                plugin_event = plugin_in_chain[list(plugin_in_chain.keys())[0]].handle(plugin_event,
                                                                                       self.plugins[plugin].config)


def parse_configs():
    from os import listdir
    from os.path import isfile, join
    only_files = [join("./honey_log/plugin/config/", f) for f in listdir("./honey_log/plugin/config/") if
                  isfile(join("./honey_log/plugin/config/", f))]
    plugins = {}
    for filename in only_files:
        plugin_configuration = PluginConfiguration(filename)
        plugins[filename] = Plugin(plugin_configuration)
    return plugins
