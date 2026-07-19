# Usage: set_mac_address.applescript <vmID> <nicIndex> <mac>
# Sets the address of the interface at nicIndex (UTM cannot generate a MAC
# through scripting — the caller supplies one).
on run argv
	set vmID to item 1 of argv
	set nicIdx to (item 2 of argv) as integer
	set macAddress to item 3 of argv
	tell application "UTM"
		set vm to virtual machine id vmID
		set config to configuration of vm
		repeat with nic in network interfaces of config
			if (index of nic) is nicIdx then set address of nic to macAddress
		end repeat
		update configuration of vm with config
	end tell
end run
