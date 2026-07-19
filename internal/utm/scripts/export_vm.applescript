# Usage: export_vm.applescript <vmID> <outputPath>
on run argv
	set vmID to item 1 of argv
	set exportPath to item 2 of argv
	set exportFile to POSIX file exportPath
	tell application "UTM"
		set vm to virtual machine id vmID
		export vm to exportFile
	end tell
end run
