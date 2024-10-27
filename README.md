## Main Components of ETW

Credit to:
https://s4dbrd.com/evading-etw-based-detections/
https://jsecurity101.medium.com/uncovering-windows-events-b4b9db7eac54
    
The four main components of the system consist of:

- Providers - Designed to generate the events. They must register with ETW and send events using the API and register a callback function to enable/disable tracing.

	To list all providers available in the system: `logman query providers`

- Sessions - Session interface designed as the intermediary that relays events from one or more providers to the consumer. This is a kernel object that gathers events into a kernel buffer and forwards them to specified files or a real-time consumer.

	To list all sessions available in the system: `logman query -ets`
	
- Controllers - Components that define and manage trace sessions. Their responsibilities:
	- Starting and stopping sessions
	- Enabling or disabling providers associated with a session
	- Managing the size of the event buffer pool
	
	A single application might contain both the controller and consumer code, or the controller can be separate, such as the `logman` utility. Controllers create trace sessions using `sechost!ControlTrace`, `advapi!EnableTraceEx` or `sechost!EnableTraceEx2`

- Consumers - The software components designed to receive events after being recorded by a trace session, either from disk or in-memory at runtime. Most EDR vendors use runtime consumers.

	Consumers use `sechost!OpenTrace` to connect to the real-time session and `sechost!ProcessTrace` to start consuming events from it. Each time the consumer receives a new event, an internally-defined callback function parses the data based on information supplied by the provider, such as an event-manifest.

	The Consumer can choose to do whatever it wishes with the incoming data. This is where EDR vendors may send off alerts to their product's interface, logging or take preventative actions, sometimes cooperating with other sensors.

![](etw.png?raw=true)

## High-Level Control Flow
Code flow for generating ETW events can be divided as such:
1. Operational Functions - Higher-level wrapper functions that perform an operation that interacts with Microsoft embedded Event Processing Functions.

2. Event Processing Functions - Undocumented Microsoft internal functions used to start the event auditing process. It's import to note that if this function isn't hit during execution then the correlating event log won't be generated.

3.  Event Emission Function - Either `ntdll!EtwWriteUMSecurityEvent` or `nt!EtwWriteKMSecurityEvent` which will start the process of writing events to the `Microsoft-Windows-Security-Auditing Provider`

Link to [Johnathan Johnson's Windows Security Auditing Spreadsheet](https://docs.google.com/spreadsheets/d/1LHBrd6XE6VhnZC6Z6otJOeHVzkRSBY7ny5VS5YJ35Kg/edit?gid=0#gid=0) with extensive mappings of process events to corresponding API calls.

## Kernel Mode ETW

There's a long list of different logging functions for ETW. I don't think I need to write them all down here, and their function names explain a lot about what they do.  `EtwTi` prepended functions are the ETW-TI sensors and `EtwTim` are mitigation sensors.

Notable domains for ETW Event creation:
- Logging memory allocation
- Logging memory read/write operations  
- Logging memory protection changes (VAD)
- Denying child process creation 
- Logging APC object insertions 
- Logging Device Object loading/unloading
- CET Compatibility checks (Log or Deny)
- Shadow Stack and Indirect Branch checks (CET)
- FSCTL checks (`NtDeviceIoControlFile` in sleep obfuscation)
- File/Folder redirection checks
- Logging `NtSetContextThread` calls
- Logging new mapped views of files or memory-mapped objects
- Logging driver object loading/unloading
- Logging suspended then resumed processes/threads
- Denying protection changes
- Denied execution ("non-compliant code") from reserved memory
- Denied execution ("non-compliant code") from mapped views
- Low integrity checks on executable images being mapped
- Denied direct system calls

Johnathan Johnson has elegantly laid-out a comprehensive map for these different calls:

![](IDA_Diagram.drawio.png?raw=true)

