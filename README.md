# Venator

Venator is a python tool used for gathering data for the purpose of proactive macOS detection. It is designed to support the native macOS python installation (2.7.x). Happy macOS Hunting!

Venator modules:

`system_info`: 
* hostname
* kernel
* kernel_release

`launch_agents`: 
* label
* program
* program_arguments
* runAtLoad
* hash
* executable
* plist_hash
* path
* hostname

`launch_daemons`:
* label
* program
* program_arguments
* runAtLoad
* hash
* executable
* plist_hash
* path
* hostname

`users`: 
* users on the system

`safari_extensions`: 
* extension name
* extension signature info
* developer identifier
* extensions path

`chrome_extensions`: 
* directory name
* extension update url
* extension name

`firefox_extensions`: 
* Extension ID
* Extension Update URL
* Extension Options URL
* Extension Install Date
* Extension Last Updated
* Extension Source URI 
* Extension Name 
* Extension Description
* Extension Creator
* Extension Homepage URL

`install_history`: 
* install date
* display name
* package identifier

`cron_jobs`: 
*  For each user show every listed cron job

`emond_rules`: 
* path
* contents of the plist for each listed in the directory

`environemnt_variables`: 
* list of the enviornment variables on the system and their values

`periodic_scripts`: 
* list of all the periodic scripts on the system

`current_connections`: 
* all connections on the system
* process name
* process id
* user
* tcp/udp
* connection flow

`sip_status`: 
* Enabled or not.

`gatekeeper_status`: 
* enabled or not.

`login_items`: 
* All login items on the system

`applications`: 
* A list of all applications on the system

`event_taps`: 
* list of all currently registered event taps
* event tap id
* tapping process id
* tapping process name
* tapped process id

`bash_history`: 
* Dump of bash history on the system