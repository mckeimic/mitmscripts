import typing
import re
from pathlib import Path

import mitmproxy.addonmanager
import mitmproxy.http
import mitmproxy.log
from mitmproxy import command, types, flow


DEFAULT_SAVE_LOCATION = Path("~/.mitmproxy/mitmscripts/no_hsts.json")


class HstsWatcher:
    """Watch for hosts which don't enable HSTS
    (https://tools.ietf.org/html/rfc6797#appendix-B). This list can be saved to
    a file whenever needed. Watching can be disabled in options. This plugin
    automatically keeps a running list of all non-HSTS domains ever observed at
    the file specified in MitmProxy Options.
    """

    HSTS_HEADER_STRING = "Strict-Transport-Security"

    # HTTP lifecycle
    def responseheaders(self, flow: mitmproxy.http.HTTPFlow):
        """
            HTTP response headers were successfully read. At this point, the body
            is empty.
        """
        if ctx.options.checkhsts and not hsts_enabled(flow):
            add_flow(flow)

    def add_flow(self, flow: mitmproxy.http.HTTPFlow):
        """Add the host from a flow to the list of hosts without HSTS configured correctly"""
        unsafe_host = get_host(flow)
        self.hosts.add(unsafe_host)

    def get_host(self, flow: mitmproxy.http.HTTPFlow):
        """Get the remote (non-user-agent) host from a specified HTTP flow"""
        return flow.request.host

    def hsts_enabled(self, flow: mitmproxy.http.HTTPFlow):
        """Check if HSTS is configured in a given HTTP flow. Return `True` if
        HSTS is configured properly."""
        if HSTS_HEADER_STRING in flow.response.headers.keys():
            return True
        return False

    def done(self):
        """
            Called when the addon shuts down, either by being removed from
            the mitmproxy instance, or when mitmproxy itself shuts down. On
            shutdown, this event is called after the event loop is
            terminated, guaranteeing that it will be the final event an addon
            sees. Note that log handlers are shut down at this point, so
            calls to log functions will produce no output.
        """
        # Ensure that our running save file exists, even if it's empty
        save_file = Path(ctx.options.CheckHSTSSaveLocation)
        if not save_file.is_file():
            save_file.parent.mkdir(exist_ok=True)
            save_file.touch(exist_ok=True)

        # Grab our non-HSTS hosts from previous saves, or just create an empty
        # set if there aren't any old saves
        with open(running_save_file, "r") as f:
            host_list = json.load(f)
            previously_known_hosts = set(host_list)

        # Add the new non-HSTS hosts from this run
        known_hosts = list(previously_known_hosts.update(self.hosts))

        # Save the set union of non-hsts hosts back to the save file
        with open(running_save_file, "w") as f:
            json.dump(known_hosts, f)

    def load(self, loader: mitmproxy.addonmanager.Loader):
        """
            Called when an addon is first loaded. This event receives a Loader
            object, which contains methods for adding options and commands. This
            method is where the addon configures itself.
        """
        loader.add_option(
            name="CheckHSTS",
            typespec=bool,
            default=True,
            help="If enabled, this plugin will maintain a list of hosts which do not have HSTS configured.",
        )
        loader.add_option(
            name="CheckHSTSSaveLocation",
            typespec=str,
            default=str(DEFAULT_SAVE_LOCATION),
            help="Define where the list of domains without HSTS will be saved to every time MitmProxy shuts down.",
        )
        self.hosts = set()

    @command.command("mitmscripts.hsts.save")
    def save_list(
        self,
        path: types.Path = str(DEFAULT_SAVE_LOCATION),
        flows: typing.Sequence[flow.Flow] = None,
    ) -> None:
        """Write the list of hosts without HSTS enabled to a file. If flows
        are provided, limit the hosts to those flows. If format is provided,
        the file will be written in the specified format."""
        if flows is None:
            no_hsts_hosts = self.hosts
        else:
            no_hsts_hosts = set()
            for flow in flows:
                if not hsts_enabled(flow):
                    unsafe_host = get_host(flow)
                    no_hsts_hosts.add(unsafe_host)

        with open(path, "w") as f:
            json.dump(list(no_hsts_hosts), f)

addons = [
            HstsWatcher()
            ]
