// Zero-downtime restarts in Go.
package goagain

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
        "runtime"
        "time"
        "sync"
        "net/http"
        "flag"
	"syscall"
)

type ReqCounter struct {
        m sync.Mutex
        c int
}

func (c ReqCounter)get() (ct int) {
        c.m.Lock()
        ct = c.c
        c.m.Unlock()
        return
}

var reqCount ReqCounter

type SupervisedConn struct {
        net.Conn
}

func (w SupervisedConn) Close() error {
        reqCount.m.Lock()
        reqCount.c--
        reqCount.m.Unlock()
        return w.Conn.Close()
}

type SupervisingListener struct {
        net.Listener
}

func (sl *SupervisingListener) Accept() (c net.Conn, err error) {
        c, err = sl.Listener.Accept()
        if err != nil {
                return
        }
        c = SupervisedConn{Conn: c}
        reqCount.m.Lock()
        reqCount.c++
        reqCount.m.Unlock()
        return
}

// Export an error equivalent to net.errClosing for use with Accept during
// a graceful exit.
var ErrClosing = errors.New("use of closed network connection")

// Block this goroutine awaiting signals.  With the exception of SIGTERM
// taking the place of SIGQUIT, signals are handled exactly as in Nginx
// and Unicorn: <http://unicorn.bogomips.org/SIGNALS.html>.
func AwaitSignals(l net.Listener) error {
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGUSR2)
	for {
		sig := <-ch
		log.Println(sig.String())
		switch sig {

		// TODO SIGHUP should reload configuration.

		// TODO SIGUSR1 should reopen logs.

		// SIGUSR2 begins the process of restarting without dropping
		// the listener passed to this function.
		case syscall.SIGUSR2:

			err := Relaunch(l)
			if nil != err {
				return err
			}
			return nil

		}
	}
	return nil // It'll never get here.
}

// Convert and validate the GOAGAIN_FD, GOAGAIN_NAME
// environment variables.  If both are present and in order, this
// is a child process that may pick up where the parent left off.
func GetEnvs() (l net.Listener, err error) {
	var fd uintptr
	_, err = fmt.Sscan(os.Getenv("GOAGAIN_FD"), &fd)
	if nil != err {
		return
	}
	var i net.Listener
	i, err = net.FileListener(os.NewFile(fd, os.Getenv("GOAGAIN_NAME")))
	if nil != err {
		return
	}
	l = i
	if err = syscall.Close(int(fd)); nil != err {
		return
	}
	return
}

// Send SIGQUIT (but really SIGTERM since Go can't handle SIGQUIT) to the
// given ppid in order to complete the handoff to the child process.
func KillParent(ppid int) error {
	err := syscall.Kill(ppid, syscall.SIGTERM)
	if nil != err {
		return err
	}
	return nil
}

// Re-exec this image without dropping the listener passed to this function.
func Relaunch(l net.Listener) error {
	argv0, err := exec.LookPath(os.Args[0])
	if nil != err {
		return err
	}
	wd, err := os.Getwd()
	if nil != err {
		return err
	}
	v := reflect.ValueOf(l).Elem().FieldByName("fd").Elem()
	fd := uintptr(v.FieldByName("sysfd").Int())
	noCloseOnExec(fd)
	if err := os.Setenv("GOAGAIN_FD", fmt.Sprint(fd)); nil != err {
		return err
	}
	if err := os.Setenv("GOAGAIN_NAME", fmt.Sprintf("tcp:%s->", l.Addr().String())); nil != err {
		return err
	}
	files := make([]*os.File, fd+1)
	files[syscall.Stdin] = os.Stdin
	files[syscall.Stdout] = os.Stdout
	files[syscall.Stderr] = os.Stderr
	files[fd] = os.NewFile(fd, string(v.FieldByName("sysfile").String()))
	p, err := os.StartProcess(argv0, os.Args, &os.ProcAttr{
		Dir:   wd,
		Env:   os.Environ(),
		Files: files,
		Sys:   &syscall.SysProcAttr{},
	})
	if nil != err {
		return err
	}
	log.Printf("spawned child %d\n", p.Pid)
	return nil
}

// Taken from upgradable.go

// These are here because there is no API in syscall for turning OFF
// close-on-exec (yet).

// from syscall/zsyscall_linux_386.go, but it seems like it might work
// for other platforms too.
func fcntl(fd int, cmd int, arg int) (val int, err error) {
        if runtime.GOOS != "linux" {
                log.Fatal("Function fcntl has not been tested on other platforms than linux.")
        }

        r0, _, e1 := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(cmd), uintptr(arg))
        val = int(r0)
        if e1 != 0 {
                err = e1
        }
        return
}

func noCloseOnExec(fd uintptr) {
        fcntl(int(fd), syscall.F_SETFD, ^syscall.FD_CLOEXEC)
}

func fclose(fd int) (err error) {
        if runtime.GOOS != "linux" {
                log.Fatal("Function fclose has not been tested on other platforms than linux.")
        }

        err = syscall.Close(fd)
        return
}

func ListenAndServe(proto string, addr string) {
	var(
		err error
		l net.Listener
		lunixaddr *net.UnixAddr
		ltcpaddr *net.TCPAddr
	)
        log.SetPrefix(fmt.Sprintf("[%s:%5d] ", os.Args[0], syscall.Getpid()))
        l, err = GetEnvs()

        if nil != err {

                log.Printf("opening socket for the first time because %s", err)
                // Listen on a TCP socket and accept connections in a new goroutine.
		if ("unix" == proto) {
	                lunixaddr, err = net.ResolveUnixAddr(proto, addr)
		} else {
	                ltcpaddr, err = net.ResolveTCPAddr(proto, addr)
		}
                if nil != err {
                        log.Println(err)
                        os.Exit(1)
                }
		if ("unix" == proto) {
	                log.Printf("listening on %v", lunixaddr)
			l, err = net.ListenUnix(proto, lunixaddr)
		} else {
	                log.Printf("listening on %v", ltcpaddr)
			l, err = net.ListenTCP(proto, ltcpaddr)
		}
                if nil != err {
                        log.Println(err)
                        os.Exit(1)
                }
                m := &SupervisingListener{Listener: l}
                go http.Serve(m, nil)

        } else {

                // Resume listening and accepting connections in a new goroutine.
                log.Printf("resuming listening on %v", l.Addr())
                m := &SupervisingListener{Listener: l}
                go http.Serve(m, nil)

        }

        // Block the main goroutine awaiting signals.
        if err := AwaitSignals(l); nil != err {
                log.Fatalln(err)
        }

	var f *os.File;

	if ("unix" == proto) {
		castedl := l.(*net.UnixListener)
	        f, err = castedl.File()
	} else {
		castedl := l.(*net.TCPListener)
	        f, err = castedl.File()
	}

        if nil != err {
             log.Fatalln(err)
        }
        err = fclose(int(f.Fd()))
        if nil != err {
             log.Fatalln(err)
        }

        log.Printf("server no longer accepting requests -- outstanding requests: %d", reqCount.get())

        for i := 0; (i < 10) && reqCount.get() > 0 ; i++ {
             log.Printf("waiting for %d outstanding requests...", reqCount.get())
             time.Sleep(1 * time.Second)
        }

        if reqCount.get() == 0 {
             log.Print("server gracefully stopped.")
             os.Exit(0)
        } else {
             log.Fatalf("server stopped after 10 seconds with %d clients still connected.", reqCount.get())
        }
}

func Run() {
        var protovar string
        var socketvar string
        flag.StringVar(&protovar, "proto", "unix", "protocol to use with socket ('unix' for UNIX sockets, 'tcp' for TCP addresses)")
        flag.StringVar(&socketvar, "socket", "/tmp/socket", "path to UNIX socket to listen on, or TCP address and port")
        flag.Parse()
        ListenAndServe(protovar, socketvar)
}
