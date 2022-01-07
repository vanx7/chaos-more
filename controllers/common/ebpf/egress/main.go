package main

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
	"os"
	"syscall"
)

func main() {
	stdin, err := unix.FcntlInt(os.Stdin.Fd(), unix.F_DUPFD_CLOEXEC, 1)
	if err != nil {
		panic(err)
	}
	old := os.Stdin
	os.Stdin = os.NewFile(uintptr(stdin), "stdin")
	old.Close()
	fd, err := unix.Open(os.DevNull, syscall.O_RDONLY, 0)
	if err != nil {
		panic(err)
	}
	if fd != 0 {
		panic(err)
	}
	prog, err := ebpf.NewProgramFromFD(fd)
	if err != nil {
		panic(err)
	}
	defer prog.Close()

	fmt.Printf("type %s, info %+v", prog.Type(), prog)

}

func testProgam() {
	spec := &ebpf.ProgramSpec{
		Type: ebpf.SocketFilter,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "MIT",
	}

	prog, err := ebpf.NewProgramWithOptions(spec, ebpf.ProgramOptions{
		LogLevel: 2,
		LogSize:  1024,
	})
	if err != nil {
		panic(err)
	}
	defer prog.Close()

	fmt.Println("The verifier output is:")
	fmt.Println(prog.VerifierLog)
}
