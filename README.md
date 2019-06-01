# Venator
![](https://github.com/richiercyrus/Venator/blob/master/images/venator4%20copy.png)

Venator is a python tool used for gathering data for the purpose of proactive macOS detection. Support for High Sierra & Mojave using native macOS python version (2.7.x). Happy Hunting! 

Accompanying blog post: https://posts.specterops.io/introducing-venator-a-macos-tool-for-proactive-detection-34055a017e56

***You may need to specify `/usr/bin/python` at command line instead of "python." if you have alternative versions of python installed.**

![](https://github.com/richiercyrus/Venator/blob/master/images/Screen%20Shot%202019-04-26%20at%203.51.35%20PM.png)
***Of note, S3 funtionality will be part of a upcoming release.**

**The script needs root permissions to run, or else you will get the error message below.**
![](https://github.com/richiercyrus/Venator/blob/development/images/Screen%20Shot%202019-03-30%20at%201.59.31%20PM.png)



Below are the Venator modules and the data each module contains. Once the script is complete, you will be provide a JSON file for futher analysis/ingestion into a SIEM solution. You can search for data by module in the following way within the JSON file:
`module:<name of module>`

`system_info`: 
* hostname
* kernel
* kernel_release

`launch_agents`: 
* label
* program
* program_arguments
* signing_info
* hash
* executable
* plist_hash
* path
* runAtLoad
* hostname

`launch_daemons`:
* label
* program
* program_arguments
* signing_info
* hash
* executable
* plist_hash
* path
* runAtLoad
* hostname

`users`: 
* users
* hostname

`safari_extensions`: 
* extension name
* apple_signed
* developer_identifier
* extension_path
* hostname

`chrome_extensions`: 
* extension_directory_name
* extension_update_url
* extension_name
* hostname

`firefox_extensions`: 
* extension_id
* extension_update_url
* extension_options_url
* extension_install_date
* extension_last_updated
* extension_source_uri 
* extension_name
* extension_description
* extension_creator
* extension_homepage_url
* hostname

`install_history`: 
* install_date
* display_name
* package_identifier
* hostname

`cron_jobs`: 
* user
* crontab
* hostname

`emond_rules`: 
* rule
* path
* hostname

`environment_variables`: 
* hostname
* variable:value

`periodic_scripts`: 
* hostname
* periodic_script:"content of script"

`current_connections`: 
* process_name
* process_id
* user
* TCP_UDP
* connection_flow
* hostname

`sip_status`: 
* sip_status
* hostname

`gatekeeper_status`: 
* gatekeeper_status
* hostname

`login_items`: 
* hostname
* application
* executable
* application_hash
* signature

`applications`: 
* hostname
* application
* executable
* application_hash
* signature

`event_taps`: 
* eventTapID
* tapping_process_id
* tapping_process_name
* tapped_process_id
* enabled
* hostname

`bash_history`: 
* user
* bash_commands
* hostname

`shell_startup`: 
* user
* hostname
* shell_startup_filename
* shell_startup_data
