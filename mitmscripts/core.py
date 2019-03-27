'''Common functionality for the mitmscripts plugins'''


def get_origin(self, flow: flow.mitmproxy.http.HTTPFlow):
    """Return a namedtuple describing the origin a flow is interacting with"""
    Origin = namedtuple("Origin", ["scheme", "host", "port"])
    return Origin(flow.request.scheme, flow.request.host, flow.request.port)
