# Usage: import_vm.applescript <utmFilePath>
# Imports a .utm bundle; the returned value prints as
# "virtual machine id <ID> ..." — the caller parses the ID.
on run argv
	set importPath to item 1 of argv
	set vmFile to POSIX file importPath
	tell application "UTM"
		set vm to import new virtual machine from vmFile
		return vm
	end tell
end run
