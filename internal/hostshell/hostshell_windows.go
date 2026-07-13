//go:build windows

package hostshell

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ConPTY host terminal (Windows 10 1809+): CreatePseudoConsole wires a pair
// of pipes to a pseudo console, and the shell process attaches to it through
// the PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE startup attribute. The attribute
// plumbing uses raw kernel32 procs because the Win32 contract passes the
// HPCON handle VALUE as the attribute (x/sys's container API only accepts
// real pointers there).
var (
	kernel32                          = windows.NewLazySystemDLL("kernel32.dll")
	procInitializeProcThreadAttrList  = kernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttribute     = kernel32.NewProc("UpdateProcThreadAttribute")
	procDeleteProcThreadAttributeList = kernel32.NewProc("DeleteProcThreadAttributeList")
)

const procThreadAttributePseudoConsole = 0x20016

// startPlatform opens PowerShell (cmd.exe fallback) attached to a fresh
// pseudo console.
func startPlatform(cols, rows int) (terminal, string, error) {
	program, err := exec.LookPath("powershell.exe")
	if err != nil {
		program, err = exec.LookPath("cmd.exe")
		if err != nil {
			return nil, "", errors.New("neither powershell.exe nor cmd.exe found on PATH")
		}
	}

	// Pipe pair: the console reads our input from inRead and writes shell
	// output into outWrite; we keep the opposite ends.
	var inRead, inWrite, outRead, outWrite windows.Handle
	if perr := windows.CreatePipe(&inRead, &inWrite, nil, 0); perr != nil {
		return nil, "", fmt.Errorf("create input pipe: %w", perr)
	}
	if perr := windows.CreatePipe(&outRead, &outWrite, nil, 0); perr != nil {
		closeHandles(inRead, inWrite)
		return nil, "", fmt.Errorf("create output pipe: %w", perr)
	}

	var console windows.Handle
	size := windows.Coord{X: int16(clampDim(cols, 80)), Y: int16(clampDim(rows, 24))}
	if cerr := windows.CreatePseudoConsole(size, inRead, outWrite, 0, &console); cerr != nil {
		closeHandles(inRead, inWrite, outRead, outWrite)
		return nil, "", fmt.Errorf("create pseudo console: %w", cerr)
	}
	// The console duplicated its pipe ends; ours close now so EOF propagates.
	closeHandles(inRead, outWrite)

	term, err := spawnAttached(program, console, inWrite, outRead)
	if err != nil {
		windows.ClosePseudoConsole(console)
		closeHandles(inWrite, outRead)
		return nil, "", err
	}
	return term, program, nil
}

// spawnAttached starts the shell process attached to the pseudo console via
// the STARTUPINFOEX attribute list.
func spawnAttached(program string, console, inWrite, outRead windows.Handle) (terminal, error) {
	// Size query first (the documented two-call pattern), then the real init
	// over caller-allocated memory.
	var attrListSize uintptr
	_, _, _ = procInitializeProcThreadAttrList.Call(0, 1, 0, uintptr(unsafe.Pointer(&attrListSize)))
	attrListBuf := make([]byte, attrListSize)
	attrList := (*windows.ProcThreadAttributeList)(unsafe.Pointer(&attrListBuf[0]))
	ret, _, lastErr := procInitializeProcThreadAttrList.Call(
		uintptr(unsafe.Pointer(attrList)), 1, 0, uintptr(unsafe.Pointer(&attrListSize)))
	if ret == 0 {
		return nil, fmt.Errorf("initialize attribute list: %w", lastErr)
	}
	ret, _, lastErr = procUpdateProcThreadAttribute.Call(
		uintptr(unsafe.Pointer(attrList)), 0, procThreadAttributePseudoConsole,
		uintptr(console), unsafe.Sizeof(console), 0, 0)
	if ret == 0 {
		_, _, _ = procDeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(attrList)))
		return nil, fmt.Errorf("attach pseudo console attribute: %w", lastErr)
	}

	siEx := windows.StartupInfoEx{ProcThreadAttributeList: attrList}
	siEx.Cb = uint32(unsafe.Sizeof(siEx))
	cmdLine, err := windows.UTF16PtrFromString(program)
	if err != nil {
		_, _, _ = procDeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(attrList)))
		return nil, err
	}
	var procInfo windows.ProcessInformation
	if cerr := windows.CreateProcess(nil, cmdLine, nil, nil, false,
		windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_UNICODE_ENVIRONMENT,
		nil, nil, &siEx.StartupInfo, &procInfo); cerr != nil {
		_, _, _ = procDeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(attrList)))
		return nil, fmt.Errorf("start %s: %w", program, cerr)
	}
	_ = windows.CloseHandle(procInfo.Thread)

	return &windowsTerminal{
		console:     console,
		process:     procInfo.Process,
		input:       os.NewFile(uintptr(inWrite), "conpty-input"),
		output:      os.NewFile(uintptr(outRead), "conpty-output"),
		attrListBuf: attrListBuf,
		attrList:    attrList,
	}, nil
}

// windowsTerminal is the ConPTY half.
type windowsTerminal struct {
	console windows.Handle
	process windows.Handle
	input   *os.File
	output  *os.File
	// attrListBuf keeps the attribute-list memory alive until Close deletes
	// the list.
	attrListBuf []byte
	attrList    *windows.ProcThreadAttributeList
}

func (t *windowsTerminal) Read(p []byte) (int, error)  { return t.output.Read(p) }
func (t *windowsTerminal) Write(p []byte) (int, error) { return t.input.Write(p) }

func (t *windowsTerminal) Resize(cols, rows int) error {
	return windows.ResizePseudoConsole(t.console, windows.Coord{
		X: int16(clampDim(cols, 80)),
		Y: int16(clampDim(rows, 24)),
	})
}

func (t *windowsTerminal) Wait() error {
	event, err := windows.WaitForSingleObject(t.process, windows.INFINITE)
	if err != nil {
		return err
	}
	if event != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("unexpected wait result %d", event)
	}
	var exitCode uint32
	if gerr := windows.GetExitCodeProcess(t.process, &exitCode); gerr == nil && exitCode != 0 {
		return fmt.Errorf("shell exited with code %d", exitCode)
	}
	return nil
}

func (t *windowsTerminal) Close() {
	// Closing the pseudo console detaches and terminates the attached client
	// and unblocks the output reader.
	windows.ClosePseudoConsole(t.console)
	_ = windows.TerminateProcess(t.process, 1)
	_ = t.input.Close()
	_ = t.output.Close()
	_, _, _ = procDeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(t.attrList)))
	t.attrListBuf = nil
	_ = windows.CloseHandle(t.process)
}

func closeHandles(handles ...windows.Handle) {
	for _, h := range handles {
		_ = windows.CloseHandle(h)
	}
}
