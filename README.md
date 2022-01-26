
# Monitorudich


Monitorudich is a process monitoring tool that monitors and logs as much information as can be extracted from an investigated process. The tool allows the user to peak behind the scenes of a running program, what information it provides the operating system, what libraries of code it uses, and to view at runtime which libraries or OS functions the program calls and exactly how.
The idea is to create a framework that accesses a selected program and reads all available information about it, exploring the PE header. Subsequently it attaches inline hooks into it’s DLL imported functions - therefore allowing for real time monitoring of the operating system function calls that can be useful in the fields of reverse engineering and malware analysis. 



## This repository is still a Work in progress
be wary that not everything in this repository is properly cleaned up, stable and configurable without knowing the spesific place of a variable to change.
Systems that are currently in work might not be clear on how to use them. in contrust main is stable but not always clean and well factored
## Features

•	Create a log of the inspected project winapi

•	Display additional info about inspected program, PE header info for example

•	Process and add additional info about the process by matching information from different areas in the process info

•	Take the raw info gathered during runtime and display it in a friendly way.

## Screenshots

![alt text](Screenshots/cmd_mainExecute_Fibonacci.exe_screenshot.png)

