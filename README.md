## CloudInject

This is a simple tool which can be used to inject a DLL into third-party AD connectors to harvest credentials.

This tool has been tested with:

* AzureAD Connect
* OKTA AD Connector
* OneLogin AD Connector

The API call hooked is `LogonUserW` which seems to be used by each AD Connector. 

## Building

To build, we can use VSCode, or use Mingw32 with:

```
x86_64-w64-mingw32-g++ Hooker/hooker.cpp -o Hooker/hooker.dll -static -shared
x86_64-w64-mingw32-g++ Injector/injector.cpp -o Injector/injector.dll -static
```

## Usage

To use this tool, simply save `hooker.dll` to a location which is readable by the AD Connector service, and then:

```
Injector.exe [PID] [DLL PATH]
```