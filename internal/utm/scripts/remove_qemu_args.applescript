# Usage: remove_qemu_args.applescript <vmID> <arg> [<arg> ...]
# Rebuilds the VM's qemu additional arguments without any whose argument
# string matches one of the given values (stopped VMs only).
on run argv
	set vmID to item 1 of argv
	set dropArgs to {}
	repeat with i from 2 to (count of argv)
		set end of dropArgs to item i of argv
	end repeat
	tell application "UTM"
		set vm to virtual machine id vmID
		set config to configuration of vm
		set keptArgs to {}
		repeat with anArg in qemu additional arguments of config
			if (argument string of anArg) is not in dropArgs then set end of keptArgs to anArg
		end repeat
		set qemu additional arguments of config to keptArgs
		update configuration of vm with config
	end tell
end run
