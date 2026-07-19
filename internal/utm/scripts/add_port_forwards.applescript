# Usage: add_port_forwards.applescript <vmID> --index <nic> "protocol,guestAddr,guestPort,hostAddr,hostPort" ...
# Appends forwards to the interface at each --index; the index must name the
# emulated interface (the only mode whose forwards take effect).
on run argv
	set vmID to item 1 of argv
	set rules to {}
	repeat with i from 2 to (count of argv) by 3
		set nicIdx to (item (i + 1) of argv) as integer
		set AppleScript's text item delimiters to ","
		set ruleParts to text items of (item (i + 2) of argv)
		set AppleScript's text item delimiters to ""
		set end of rules to {idx:nicIdx, protocolCode:item 1 of ruleParts, guestAddr:item 2 of ruleParts, guestPortNum:(item 3 of ruleParts) as integer, hostAddr:item 4 of ruleParts, hostPortNum:(item 5 of ruleParts) as integer}
	end repeat
	tell application "UTM"
		set vm to virtual machine id vmID
		set config to configuration of vm
		repeat with nic in network interfaces of config
			repeat with aRule in rules
				if (idx of aRule) is (index of nic) then
					set pfList to port forwards of nic
					set end of pfList to {protocol:(protocolCode of aRule), guest address:(guestAddr of aRule), guest port:(guestPortNum of aRule), host address:(hostAddr of aRule), host port:(hostPortNum of aRule)}
					set port forwards of nic to pfList
				end if
			end repeat
		end repeat
		update configuration of vm with config
	end tell
end run
