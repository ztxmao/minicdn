package main

import (
	"bytes"
	"flag"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ztxmao/groupcache"
)

type ctxFlush struct {
	isFlush bool
}

func (ctx *ctxFlush) Flush() bool {
	return ctx.isFlush
}

func redirectPolicyFunc(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

var thumbNails = groupcache.NewGroup("thumbnail", 512<<20, groupcache.GetterFunc(
	func(ctx groupcache.Context, key string, dest groupcache.Sink) error {
		fileName := key
		bytes, err := generateThumbnail(fileName)
		if err != nil {
			return err
		}
		dest.SetBytes(bytes)
		return nil
	}))

func generateThumbnail(key string) ([]byte, error) {
	u, _ := url.Parse(*mirror + key)
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	if *host != "" {
		req.Host = *host
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}

func tunnel(r *http.Request) ([]byte, http.Header, error) {
	u, _ := url.Parse(*mirror)
	u.Path = r.URL.Path
	u.RawPath = r.URL.RawPath
	u.RawQuery = r.URL.RawQuery
	r.ParseForm()
	client := &http.Client{
		CheckRedirect: redirectPolicyFunc,
	}
	req, err := http.NewRequest(r.Method, u.String(), strings.NewReader(r.Form.Encode()))
	if err != nil {
		return nil, nil, err
	}
	if *host != "" {
		req.Host = *host
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Connection", "Keep-Alive")
	//resp, err := http.DefaultClient.Do(req)
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	return data, resp.Header, err
}

func cacheTunnel(w http.ResponseWriter, r *http.Request) ([]byte, http.Header, error) {
	var key string
	if *rule == "ignore" {
		key = r.URL.Path
	}
	if *rule == "copy" {
		key = r.URL.String()
	}
	state.addActiveDownload(1)
	defer state.addActiveDownload(-1)

	if *upstream == "" { // Master
		if slaveAddr, err := slaveMap.PeekSlave(); err == nil {
			u, _ := url.Parse(slaveAddr)
			u.Path = r.URL.Path
			u.RawQuery = r.URL.RawQuery
			http.Redirect(w, r, u.String(), 302)
			return nil, nil, nil
		}
	}
	fmt.Println("KEY:", key)

	ctx := &ctxFlush{}
	var data []byte
	flush := html.EscapeString(r.FormValue("_flush"))
	if flush == "^_^" {
		ctx.isFlush = true
	}
	err := thumbNails.Get(ctx, key, groupcache.AllocatingByteSliceSink(&data))
	return data, nil, err
}
func FileHandler(w http.ResponseWriter, r *http.Request) {
	method := r.Method
	key := r.URL.Path
	var data []byte
	var err error
	var header http.Header
	fmt.Println(method, *rule)
	if method == "GET" && *rule != "proxy" {
		data, header, err = cacheTunnel(w, r)
	} else {
		data, header, err = tunnel(r)
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	var modTime time.Time = time.Now()

	rd := bytes.NewReader(data)
	if header != nil {
		for key, val := range header {
			for _, v := range val {
				w.Header().Set(key, v)
			}
		}
	} else {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Cookie,Set-Cookie,x-requested-with,content-type")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
	}
	w.Header().Set("Via-Server", "goproxy cache")
	if url := w.Header().Get("Location"); url != "" {
		http.Redirect(w, r, url, 302)
	} else {
		http.ServeContent(w, r, filepath.Base(key), modTime, rd)
	}
}

var (
	mirror    = flag.String("mirror", "", "Mirror Web Base URL")
	logfile   = flag.String("log", "-", "Set log file, default STDOUT")
	upstream  = flag.String("upstream", "", "Server base URL, conflict with -mirror")
	address   = flag.String("addr", ":5000", "Listen address")
	token     = flag.String("token", "1234567890ABCDEFG", "slave and master token should be same")
	host      = flag.String("host", "", "server http host name")
	rule      = flag.String("rule", "ignore", "ignore:忽略URL参数；copy:遵循源站;proxy:透明穿透")
	cachetime = flag.Int("t", 0, "缓存时间")
)

func InitSignal() {
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for {
			s := <-sig
			fmt.Println("Got signal:", s)
			if state.Closed {
				fmt.Println("Cold close !!!")
				os.Exit(1)
			}
			fmt.Println("Warm close, waiting ...")
			go func() {
				state.Close()
				os.Exit(0)
			}()
		}
	}()
}

func main() {
	flag.Parse()

	if *mirror != "" && *upstream != "" {
		log.Fatal("Can't set both -mirror and -upstream")
	}
	if *mirror == "" && *upstream == "" {
		log.Fatal("Must set one of -mirror and -upstream")
	}
	if *upstream != "" {
		if err := InitSlave(); err != nil {
			log.Fatal(err)
		}
	}
	if *mirror != "" {
		if _, err := url.Parse(*mirror); err != nil {
			log.Fatal(err)
		}
		if err := InitMaster(); err != nil {
			log.Fatal(err)
		}
	}

	InitSignal()
	//fmt.Println("Hello CDN")
	http.HandleFunc("/", FileHandler)
	log.Printf("Listening on %s", *address)
	log.Fatal(http.ListenAndServe(*address, nil))
}
