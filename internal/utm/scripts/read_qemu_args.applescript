# Usage: read_qemu_args.applescript <vmID>
# Emits each qemu additional argument string verbatim, one per line.
on run argv
	set vmID to item 1 of argv
	tell application "UTM"
		set vm to virtual machine id vmID
		set config to configuration of vm
		repeat with anArg in qemu additional arguments of config
			log (argument string of anArg)
		end repeat
	end tell
end run
