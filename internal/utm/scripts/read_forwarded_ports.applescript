# Usage: read_forwarded_ports.applescript <vmID>
# Emits the emulated interface's forwards as
# Forwarding(<nicIndex>)(<ruleIndex>)="protocol,guestAddr,guestPort,hostAddr,hostPort"
# lines — port forwards exist only on the emulated mode.
on run argv
	set vmID to item 1 of argv
	tell application "UTM"
		set vm to virtual machine id vmID
		set config to configuration of vm
		repeat with nic in network interfaces of config
			if (mode of nic as string) is "emulated" then
				set ruleIndex to -1
				repeat with pf in port forwards of nic
					set ruleIndex to ruleIndex + 1
					set lineText to "Forwarding(" & (index of nic) & ")(" & ruleIndex & ")=\""
					set lineText to lineText & (protocol of pf) & "," & (guest address of pf)
					set lineText to lineText & "," & (guest port of pf) & "," & (host address of pf)
					set lineText to lineText & "," & (host port of pf) & "\""
					log lineText
				end repeat
			end if
		end repeat
	end tell
end run
