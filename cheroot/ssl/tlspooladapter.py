"""Implementation of the SSL Adapter for the TLS Pool."""


from . import Adapter

from ..makefile import StreamReader, StreamWriter

import tlspool


try:
    from _pyio import DEFAULT_BUFFER_SIZE
except ImportError:
    try:
        from io import DEFAULT_BUFFER_SIZE
    except ImportError:
        DEFAULT_BUFFER_SIZE = -1


class TLSPoolAdapter (Adapter):

    """The TLS Pool is a separate daemon implementing TLS in a
       separate process, so as to keep long-term credentials
       and the management of TLS away from application logic.
       This is perfect for a dynamic, pluggable environment
       that might integrate scripts from a variety of mildly
       unknown sources.  It is generally good to contain the
       problems resulting from an application breach.
    """

    def __init__ (self, server_name):
        """Initialise this object and ignore the customary
           things: cert, key, chain, ciphers are all handled
           by the TLS Pool, so we can be blissfully ignorant.
        """
        self.server_name = server_name

    def bind (self, sock):
        """Wrap and return the socket.
           TODO: Wrapping is not done here, as in Builtin?!?
        """
        return super (TLSPoolAdapter,self).bind (sock)

    def wrap (self, extsock):
        """Wrap the given socket in TLS and return the result,
           along with WSGI environment variables in a tuple.
        """
	fl = ( tlspool.PIOF_STARTTLS_LOCALROLE_SERVER |
	       tlspool.PIOF_STARTTLS_REMOTEROLE_CLIENT |
               tlspool.PIOF_STARTTLS_IGNORE_REMOTEID )
	hdl = tlspool.Connection (extsock, service='http', flags=fl)
	hdl.tlsdata.localid = self.server_name
	intsock = hdl.starttls ()
        env = {
                'wsgi.url_scheme': 'https',
                'HTTPS': 'on',
                'LOCAL_USER': hdl.tlsdata.localid,
                'REMOTE_USER': hdl.tlsdata.remoteid,
        }
        return intsock, env

    def makefile(self, sock, mode='r', bufsize=DEFAULT_BUFFER_SIZE):
        """Return socket file object."""
        cls = StreamReader if 'r' in mode else StreamWriter
        return cls(sock, mode, bufsize)

    def get_environ (self, sock):
        """Return WSGI variables to be merged into each request.
        """
        return {
                'wsgi.url_scheme': 'https',
                'HTTPS': 'on',
        }

