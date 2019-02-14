# Venator
Venator is a python tool used for gathering data for the purpose of proactive macOS detection. It is designed to support the native macOS python installation (2.7.x). Happy macOS Hunting!

Detection Items:
System Info: hostname, kernel, kernel release
Launch Agents: label, program, program arguments, run at load status, hash, path of launch agent
Launch Daemons:label, program, program arguments, run at load status, hash, path of launch daemon
Users: users on the system
Safari Extensions: extension name, extension signature info, developer identifier, extensions path
Chrome Extensions: directory name, extension update url, extension name
Install History: install date, display name, package identifier
Cron Jobs: For each user show every listed cron job
Emond rules: path, contents of the plist for each listed in the directory
Environemnt Variables: list of the enviornment variables on the system and their values
Periodic Scripts: list of all the periodic scripts on the system
Current connections: all connections on the system, process name, process id, user, tcp/udp, connection flow
System Integrity Protection status: Enabled or not.
Gatekeeper Status: enabled or not.
Login Items: All login items on the system
Applications: A list of all applications on the system
Event Taps: list of all currently registered event taps, event tap id, tapping process id, tapping process name, tapped process id
Bash history: Dump of bash history on the system