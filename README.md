# NSOverride
Injectable DLL to override the DNS servers used by a Windows process

As the only results I could find on the Internet were about overriding DNS results instead of the DNS servers used, I wrote NSOverride, which I have tested in Chrome (as a proxy DLL) and Firefox on both Windows 8.1 and 10. (Windows 7 may work, XP probably not.)

How it works:

* The Winsock functions get the system DNS addresses from the `GetAdaptersAddresses` function, which reads the Registry to find said addresses. By hooking, thanks to Detours, the `RegQueryValueExA` function it uses we can supply our own addresses in lieu.

* However, dnsapi.dll forwards requests to the DNSCache service via RPC if it is running, meaning resolution is done out of process and our hook won't have any effect unless usually the DNSCache service is disabled (something quite hard to do in the latest Windows 10 versions). So this DLL also hooks `RpcBindingCreateW` and prevents the connection to DNSCache's ALPC Port, forcing resolution to happen in-process.

How to use:

Set the NAMESERVER environment variable to a list of DNS addresses, comma-delimited with no spaces. (Ex. `set NAMESERVER=8.8.8.8,1.1.1.1`)
Use your favourite DLL injector to load the DLL into the target process before it gets a chance to do its Winsock duties.

You could wrap the code in a proxy DLL, see [this](https://github.com/zeffy/proxydll_template) for templates. For Chrome, version.dll works well.

For 32-bit Windows, the prebuilt DLL and VS project file assume SysWOW64. 

On Linux, use [resolvconf-override](https://github.com/hadess/resolvconf-override) which works great with Chromium.
