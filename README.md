# SimpleCodeInjection
A Simple code injection poc that creats a remote thread under a process.

## Usage
The script requires the user to enter the process id or name, followed by the a file containing the shellcode we would want to inject.

The payload should be written in bytes format, as the script reads it in 'rb' mode.

After the execution, the script will print the remote process id, along with the size of the shellcode given, and the new malicious thread id:
![Demonstration](https://i.imgur.com/FDMf9vx.png)

By looking at process explorer we can see that our new thread has been created with id of 11600:
![Demonstration](https://i.imgur.com/etuIXXX.png)
