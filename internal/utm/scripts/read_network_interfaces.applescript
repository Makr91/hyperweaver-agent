# Usage: read_network_interfaces.applescript <vmID>
# Emits one line per interface: nic<index>,<mode> (log lands on stderr).
on run argv
	set vmID to item 1 of argv
	tell application "UTM"
		set vm to virtual machine id vmID
		set config to configuration of vm
		repeat with nic in network interfaces of config
			log "nic" & (index of nic) & "," & (mode of nic)
		end repeat
	end tell
end run
