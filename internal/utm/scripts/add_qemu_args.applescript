# Usage: add_qemu_args.applescript <vmID> <arg> [<arg> ...]
# Appends each argument to the VM's qemu additional arguments (stopped VMs only).
on run argv
	set vmID to item 1 of argv
	set newArgs to {}
	repeat with i from 2 to (count of argv)
		set end of newArgs to item i of argv
	end repeat
	tell application "UTM"
		set vm to virtual machine id vmID
		set config to configuration of vm
		set argList to qemu additional arguments of config
		repeat with anArg in newArgs
			set end of argList to {argument string:(contents of anArg)}
		end repeat
		set qemu additional arguments of config to argList
		update configuration of vm with config
	end tell
end run
