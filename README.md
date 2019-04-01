# Venator

Venator is a python tool used for gathering data for the purpose of proactive macOS detection. Support for High Sierra & Mojave using native macOS python version (2.7.x). Happy Hunting!

"Placeholder for the run as root error message"

"Placeholder for the HELP menu"

`Of note, S3 funtionality will be part of a upcoming release.`

Below are the Venator modules and the data each module contains. Once the script is complete, you can search for data by module in the following way:
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