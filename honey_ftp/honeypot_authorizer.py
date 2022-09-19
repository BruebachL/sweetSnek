from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed

from honey_log.honeypot_event import HoneyPotLoginEventContent


class HoneyPotAuthorizer(DummyAuthorizer):

    def __init__(self, logging_client):
        super().__init__()
        self.logging_client = logging_client

    def validate_authentication(self, username, password, handler):
        """Raises AuthenticationFailed if supplied username and
                password don't match the stored credentials, else return
                None.
                """
        self.logging_client.report_event("login", HoneyPotLoginEventContent(handler.remote_ip, "FTP", username, password))
        msg = "Authentication failed."
        raise AuthenticationFailed(msg)
        if not self.has_user(username):
            if username == 'anonymous':
                msg = "Anonymous access not allowed."
            raise AuthenticationFailed(msg)
        if username != 'anonymous':
            if self.user_table[username]['pwd'] != password:
                raise AuthenticationFailed(msg)
