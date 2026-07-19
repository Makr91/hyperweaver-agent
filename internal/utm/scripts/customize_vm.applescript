# Usage: customize_vm.applescript <vmID> [--name N] [--cpus C] [--memory MB] [--notes T] [--share-mode SmOf|SmWv|SmVs]
# Applies only the flags given; the VM must be stopped for the update to save.
on run argv
	set vmID to item 1 of argv
	set newName to ""
	set newCPUs to 0
	set newMemory to 0
	set newNotes to ""
	set shareMode to ""
	repeat with i from 2 to (count of argv)
		set flagArg to item i of argv
		if flagArg is "--name" then
			set newName to item (i + 1) of argv
		else if flagArg is "--cpus" then
			set newCPUs to (item (i + 1) of argv) as integer
		else if flagArg is "--memory" then
			set newMemory to (item (i + 1) of argv) as integer
		else if flagArg is "--notes" then
			set newNotes to item (i + 1) of argv
		else if flagArg is "--share-mode" then
			set shareMode to item (i + 1) of argv
		end if
	end repeat
	tell application "UTM"
		set vm to virtual machine id vmID
		set config to configuration of vm
		if newName is not "" then set name of config to newName
		if newCPUs is not 0 then set cpu cores of config to newCPUs
		if newMemory is not 0 then set memory of config to newMemory
		if newNotes is not "" then set notes of config to newNotes
		if shareMode is not "" then set directory share mode of config to shareMode
		update configuration of vm with config
	end tell
end run
