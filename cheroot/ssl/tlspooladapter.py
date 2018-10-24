"""Implementation of the SSL Adapter for the TLS Pool.

When you use cheroot directly, you can specify an
`ssl_adapter` set to an instance of this class.
Using the WSGI standard example, you might adapt
it thusly:

    from cheroot import wsgi
    from cheroot.ssl.tlspooladapter import TLSPoolAdapter
    
    def my_crazy_app(environ, start_response):
        status = '200 OK'
        response_headers = [('Content-type','text/plain')]
        start_response(status, response_headers)
        return [b'Hello world!\r\nThis is the TLS Pool variant of cheroot\r\n']
    
    addr = '0.0.0.0', 8070
    server = wsgi.Server(addr, my_crazy_app, server_name='tlspool.arpa2.lab')
    server.ssl_adapter = TLSPoolAdapter ('tlspool.arpa2.lab')
    server.start()

In comparison to the standard WSGI server, you have added
one `import` line and set the `server.ssl_adaptor` to an
instance of the plugin class defined in this module.

The idea of the TLS Pool is to isolate long-term credentials
from application code.  This allows code to be more freely
developed, and an occasional security breach to never get to
the crown jewels of the site, thanks to the strict separation
of processes maintained by the operating system.  It also
allows central management of credentials, which is a nuisance
up to a point of a certain scale, where it becomes divine.
The intention of the InternetWide Architecture and specifically
the IdentityHub is to automate so much of the flow surrounding
the TLS Pool that this point of divinity is at zero.  More on
http://internetwide.org -- yes, insecure as it is just a blog,
so the burden of management is avoided until our tools make
it a breeze!
"""


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

           This __init__() function is not the usual one
           being called; instead, the Adapter base class
           promises a function with four arguments that
           is normally called by the environment.
        """
        self.server_name = server_name

    def __init__ (self, server_name, *mooh):
        """The other plugins in this directory expect 4 args,
           namely cert, key, chain, ciphers.  This information
           is moot (or mooh) to this Adapter because management
           issues like that are centralised to the TLS Pool.
           You are however permitted to provide all four args,
           where the first (usually the certificate path) is
           interpreted as the server name.  The TLS Pool will
           look for a certificate to go with that.
        """
        self.__init__ (server_name)

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

