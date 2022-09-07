import importlib


def load_plugin(plugin_to_load):
    plugin = {}
    try:
        mymodule = importlib.import_module('honey_log.plugin.' + plugin_to_load)
        plugin[plugin_to_load] = mymodule

    except Exception as e:
        import traceback
        traceback.print_exc()
    return plugin


def load_plugin_chain(plugin_chain_to_load):
    loaded_plugins = []
    for plugin in plugin_chain_to_load:
        loaded_plugins.append(load_plugin(plugin))
    return loaded_plugins


class Plugin:

    def __init__(self, config):
        self.config = config
        self.name = config.config['Name'][0]
        self.plugin_chain = load_plugin_chain(config.config['PluginChain'])
