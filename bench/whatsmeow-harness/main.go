package main

// Live latency harness for whatsmeow (benchmark only — NOT used by ruwa).
// Pairs via QR, exposes /qr, /status, and /lat?to=NUM which sends a text and
// returns ms until the delivery receipt — the same send->delivery metric used
// for the Evolution comparison.

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"go.mau.fi/whatsmeow"
	waE2E "go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
	"google.golang.org/protobuf/proto"
)

var (
	cli       *whatsmeow.Client
	curQR     string
	qrMu      sync.Mutex
	delivered = map[string]time.Time{}
	dMu       sync.Mutex
)

func onEvent(evt interface{}) {
	if r, ok := evt.(*events.Receipt); ok {
		fmt.Printf("RECEIPT type=%q ids=%v from=%s\n", string(r.Type), r.MessageIDs, r.Chat.String())
		// Delivered ("") or Read = recipient device has the message. (retry/sender excluded.)
		if r.Type == types.ReceiptTypeDelivered || r.Type == types.ReceiptTypeRead {
			now := time.Now()
			dMu.Lock()
			for _, id := range r.MessageIDs {
				delivered[id] = now
			}
			dMu.Unlock()
		}
	}
	// READER mode: an inbound message arrived + was decrypted. POST its text to
	// the unified H2H receiver so its arrival is timestamped on the same clock as
	// the ruwa + Evolution readers. The text carries the per-message token.
	if m, ok := evt.(*events.Message); ok {
		txt := m.Message.GetConversation()
		if txt == "" {
			txt = m.Message.GetExtendedTextMessage().GetText()
		}
		if txt != "" {
			go func(t string) {
				_, _ = http.Post("http://127.0.0.1:9097/wm", "text/plain", strings.NewReader(t))
			}(txt)
		}
	}
}

func main() {
	ctx := context.Background()
	dbPath := os.Getenv("WM_DB")
	if dbPath == "" {
		dbPath = "/tmp/wm-live.db"
	}
	container, err := sqlstore.New(ctx, "sqlite3", "file:"+dbPath+"?_foreign_keys=on", waLog.Noop)
	if err != nil {
		panic(err)
	}
	device, err := container.GetFirstDevice(ctx)
	if err != nil {
		panic(err)
	}
	wlog := waLog.Noop
	if os.Getenv("WM_DEBUG") != "" {
		wlog = waLog.Stdout("WM", "DEBUG", false)
	}
	cli = whatsmeow.NewClient(device, wlog)
	cli.AddEventHandler(onEvent)

	if cli.Store.ID == nil {
		qrChan, _ := cli.GetQRChannel(ctx)
		if err := cli.Connect(); err != nil {
			panic(err)
		}
		go func() {
			for evt := range qrChan {
				qrMu.Lock()
				if evt.Event == "code" {
					curQR = evt.Code
				} else {
					curQR = "EVENT:" + evt.Event
				}
				qrMu.Unlock()
			}
		}()
	} else {
		if err := cli.Connect(); err != nil {
			panic(err)
		}
	}

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })
	http.HandleFunc("/qr", func(w http.ResponseWriter, r *http.Request) {
		qrMu.Lock()
		defer qrMu.Unlock()
		fmt.Fprint(w, curQR)
	})
	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		st := "no-session"
		if cli.Store.ID != nil {
			if cli.IsConnected() && cli.IsLoggedIn() {
				st = "connected"
			} else {
				st = "connecting"
			}
		}
		fmt.Fprint(w, st)
	})
	http.HandleFunc("/jid", func(w http.ResponseWriter, r *http.Request) {
		if cli.Store.ID != nil {
			fmt.Fprint(w, cli.Store.ID.String())
		} else {
			fmt.Fprint(w, "none")
		}
	})
	// /send?to=NUM&text=TXT : fire-and-return; sends immediately, returns the
	// message id. Used when an external observer (recipient device) times arrival.
	http.HandleFunc("/send", func(w http.ResponseWriter, r *http.Request) {
		to := r.URL.Query().Get("to")
		text := r.URL.Query().Get("text")
		if to == "" || text == "" {
			w.WriteHeader(400)
			fmt.Fprint(w, "missing ?to= or ?text=")
			return
		}
		jid := types.JID{User: to, Server: types.DefaultUserServer}
		resp, err := cli.SendMessage(ctx, jid, &waE2E.Message{Conversation: proto.String(text)})
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(w, "send err: %v", err)
			return
		}
		fmt.Fprint(w, resp.ID)
	})
	// /lat?to=NUM : send a probe, wait for the delivery receipt, return latency ms.
	http.HandleFunc("/lat", func(w http.ResponseWriter, r *http.Request) {
		to := r.URL.Query().Get("to")
		if to == "" {
			w.WriteHeader(400)
			fmt.Fprint(w, "missing ?to=")
			return
		}
		jid := types.JID{User: to, Server: types.DefaultUserServer}
		text := fmt.Sprintf("WM probe %d", time.Now().UnixNano())
		t0 := time.Now()
		resp, err := cli.SendMessage(ctx, jid, &waE2E.Message{Conversation: proto.String(text)})
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(w, "send err: %v", err)
			return
		}
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			dMu.Lock()
			t1, ok := delivered[resp.ID]
			dMu.Unlock()
			if ok {
				fmt.Fprintf(w, "%d", t1.Sub(t0).Milliseconds())
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		w.WriteHeader(504)
		fmt.Fprint(w, "no delivery receipt")
	})
	fmt.Println("wmharness listening on 127.0.0.1:8077")
	http.ListenAndServe("127.0.0.1:8077", nil)
}
