import os

from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed

from honey_log.honeypot_event import HoneyPotLoginEventContent


class HoneyPotAuthorizer(DummyAuthorizer):

    def __init__(self, logging_client, interaction_mode):
        super().__init__()
        self.logging_client = logging_client
        self.low_interaction_mode = interaction_mode

    def validate_authentication(self, username, password, handler):
        """Raises AuthenticationFailed if supplied username and
                password don't match the stored credentials, else return
                None.
                """
        self.logging_client.report_event("login", HoneyPotLoginEventContent(handler.remote_ip, "FTP", username, password))
        msg = "Authentication failed."
        if self.low_interaction_mode:
            raise AuthenticationFailed(msg)
        if not self.has_user(username):
            if username == 'anonymous':
                msg = "Anonymous access not allowed."
                raise AuthenticationFailed(msg)
            path = os.path.join("/tmp/malware/ftp/", username)
            if not os.path.exists(path):
                os.mkdir(path, mode=0o666)
            self.add_user(username, password, "/tmp/malware/ftp/" + username, perm="elradfmwMT")
        if username != 'anonymous':
            if self.user_table[username]['pwd'] != password:
                raise AuthenticationFailed(msg)
