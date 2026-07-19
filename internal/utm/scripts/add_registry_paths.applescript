# Usage: add_registry_paths.applescript <vmID> <path> [<path> ...]
# Appends each path to the VM's registry — the sandbox file-access grant a
# shared folder needs before UTM may open it.
on run argv
	set vmID to item 1 of argv
	set fileList to {}
	repeat with i from 2 to (count of argv)
		set end of fileList to POSIX file (item i of argv)
	end repeat
	tell application "UTM"
		set vm to virtual machine id vmID
		set reg to registry of vm
		set reg to reg & fileList
		update registry of vm with reg
	end tell
end run
