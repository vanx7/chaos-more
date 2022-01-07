package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"fmt"
	"github.com/cilium/ebpf"
)

var (
	binPath = "/bin/bash"
	symbol  = "readline"
)

// htons converts the unsigned short integer hostshort from host byte order to network byte order.
func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func sllleeep(test, second, third string) {
	for {
		time.Sleep(5 * time.Second)
		log.Println(test)
		_, _ = net.LookupHost("baidu.com")
		t := time.Now()
		fn := strconv.Itoa(int(t.UnixNano()))
		ioutil.WriteFile(fn, []byte{}, 0644)
		os.Remove(fn)
	}
}

func openRawSock(index int) (int, error) {
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return 0, err
	}
	sll := syscall.SockaddrLinklayer{
		Ifindex:  index,
		Protocol: htons(syscall.ETH_P_ALL),
	}
	if err := syscall.Bind(sock, &sll); err != nil {
		return 0, err
	}
	return sock, nil
}

func main() {
	var pid int
	var err error
	if len(os.Args) >= 2 {
		pid, _ = strconv.Atoi(os.Args[1])
	}
	if pid == 0 {
		pid = os.Getpid()
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	rlimit.RemoveMemlock()
	f := "/tmp/hello.o"

	coll, err := ebpf.LoadCollection(f)
	if err != nil {
		panic(err)
	}
	fmt.Printf("collection %+v \n", coll)
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	var prog *ebpf.Program
	var ebpfMap *ebpf.Map
	var name string
	for _, p := range coll.Programs {
		prog = p
	}
	for n, m := range coll.Maps {
		ebpfMap = m
		name = n
	}
	defer prog.Close()
	defer ebpfMap.Close()

	fmt.Printf("prog type: %s\n", prog.Type())
	fmt.Printf("map type: %s, name: %s fd: %d\n", ebpfMap.String(), name, ebpfMap.FD())

	if err != nil {
		panic(err)
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	ex, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup/user.slice",
		Attach:  ebpf.AttachCGroupSockOps,
		Program: prog,
	})
	if err != nil {
		log.Fatalf("opening executable: %s", err)
	}
	defer ex.Close()

	go func() {
		<-stopper
	}()

	go sllleeep("Hello from hackathon!", "second hello", "third hello")

	log.Println("Waiting for events..")

	ticker := time.NewTicker(1 * time.Second)

	var key [44]byte
	for range ticker.C {
		var value uint32
		if err := ebpfMap.Lookup(key, &value); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		log.Printf("number of packets: %d\n", value)
	}
}
