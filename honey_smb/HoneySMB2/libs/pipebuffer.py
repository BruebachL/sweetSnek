from queue import Queue


class PipeBuffer:

    def __init__(self, fileID):
        self.fileID = fileID
        self.buffer = []
        self.fileHandle = ""
        self.fileName = ""
