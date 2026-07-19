# Usage: clear_port_forwards.applescript <vmID> --index <nic> <hostPort> ...
# Rebuilds each named interface's forward list without the given host ports.
on run argv
	set vmID to item 1 of argv
	set removals to {}
	repeat with i from 2 to (count of argv) by 3
		set end of removals to {idx:(item (i + 1) of argv) as integer, hostPortNum:(item (i + 2) of argv) as integer}
	end repeat
	tell application "UTM"
		set vm to virtual machine id vmID
		set config to configuration of vm
		repeat with nic in network interfaces of config
			repeat with removal in removals
				if (index of nic) is (idx of removal) then
					set keptForwards to {}
					repeat with pf in port forwards of nic
						if (host port of pf) is not (hostPortNum of removal) then set end of keptForwards to pf
					end repeat
					set port forwards of nic to keptForwards
				end if
			end repeat
		end repeat
		update configuration of vm with config
	end tell
end run
