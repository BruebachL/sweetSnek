from pyftpdlib.filesystems import AbstractedFS


class HoneyPotFS(AbstractedFS):

    def __init__(self, root, cmd_channel):
        super().__init__(root, cmd_channel)
