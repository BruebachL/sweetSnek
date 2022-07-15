#!/usr/bin/env python
# -*- coding: utf-8 -*-
from subprocess import Popen, PIPE
import time
import signal
import os

DN = open(os.devnull, 'w')
ERRLOG = open(os.devnull, 'w')
OUTLOG = open(os.devnull, 'w')


class Process(object):
    ''' Represents a running/ran process '''

    @staticmethod
    def devnull():
        ''' Helper method for opening devnull '''
        return open('/dev/null', 'w')

    @staticmethod
    def call(command, cwd=None, shell=False):
        '''
            Calls a command (either string or list of args).
            Returns tuple:
                (stdout, stderr)
        '''
        if type(command) is not str or ' ' in command or shell:
            shell = True
        else:
            shell = False

        pid = Popen(command, cwd=cwd, stdout=PIPE, stderr=PIPE, shell=shell)
        pid.wait()
        (stdout, stderr) = pid.communicate()

        # Python 3 compatibility
        if type(stdout) is bytes: stdout = stdout.decode('utf-8')
        if type(stderr) is bytes: stderr = stderr.decode('utf-8')

        return (stdout, stderr)

    @staticmethod
    def exists(program):
        ''' Checks if program is installed on this system '''
        p = Process(['which', program])
        stdout = p.stdout().strip()
        stderr = p.stderr().strip()

        if stdout == '' and stderr == '':
            return False

        return True

    def __init__(self, command, devnull=False, stdout=PIPE, stderr=PIPE, cwd=None, bufsize=0, stdin=PIPE):
        ''' Starts executing command '''

        if type(command) is str:
            # Commands have to be a list
            command = command.split(' ')

        self.command = command

        self.out = None
        self.err = None
        if devnull:
            sout = Process.devnull()
            serr = Process.devnull()
        else:
            sout = stdout
            serr = stderr

        self.start_time = time.time()

        self.pid = Popen(command, stdout=sout, stderr=serr, stdin=stdin, cwd=cwd, bufsize=bufsize)

    def __del__(self):
        '''
            Ran when object is GC'd.
            If process is still running at this point, it should die.
        '''
        try:
            if self.pid and self.pid.poll() is None:
                self.interrupt()
        except AttributeError:
            pass

    def stdout(self):
        ''' Waits for process to finish, returns stdout output '''
        self.get_output()
        return self.out

    def stderr(self):
        ''' Waits for process to finish, returns stderr output '''
        self.get_output()
        return self.err

    def stdoutln(self):
        return self.pid.stdout.readline()

    def stderrln(self):
        return self.pid.stderr.readline()

    def stdin(self, text):
        if self.pid.stdin:
            self.pid.stdin.write(text.encode('utf-8'))
            self.pid.stdin.flush()

    def get_output(self):
        ''' Waits for process to finish, sets stdout & stderr '''
        if self.pid.poll() is None:
            self.pid.wait()
        if self.out is None:
            (self.out, self.err) = self.pid.communicate()

        if type(self.out) is bytes:
            self.out = str(self.out.decode('utf-8'))

        if type(self.err) is bytes:
            self.err = str(self.err.decode('utf-8'))

        return self.out, self.err

    def poll(self):
        ''' Returns exit code if process is dead, otherwise 'None' '''
        return self.pid.poll()

    def wait(self):
        self.pid.wait()

    def running_time(self):
        ''' Returns number of seconds since process was started '''
        return int(time.time() - self.start_time)

    def interrupt(self, wait_time=2.0):
        '''
            Send interrupt to current process.
            If process fails to exit within `wait_time` seconds, terminates it.
        '''
        try:
            pid = self.pid.pid
            cmd = self.command
            if type(cmd) is list:
                cmd = ' '.join(str(cmd))

            os.kill(pid, signal.SIGINT)

            start_time = time.time()  # Time since Interrupt was sent
            while self.pid.poll() is None:
                # Process is still running
                time.sleep(0.1)
                if time.time() - start_time > wait_time:
                    # We waited too long for process to die, terminate it.
                    os.kill(pid, signal.SIGKILL)
                    self.pid.kill()
                    break

        except OSError as e:
            if 'No such process' in e.__str__():
                return
            raise e  # process cannot be killed
