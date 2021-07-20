package httpsig_test

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/jbowes/httpsig"
)

const secret = "support-your-local-cat-bonnet-store"

func Example_round_trip() {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "Your request has a valid signature!")
	})

	middleware := httpsig.NewVerifyMiddleware(httpsig.WithHmacSha256("key1", []byte(secret)))
	http.Handle("/", middleware(h))
	go func() { _ = http.ListenAndServe("127.0.0.1:1234", http.DefaultServeMux) }()

	// Give the server time to sleep. Terrible, I know.
	time.Sleep(100 * time.Millisecond)

	client := http.Client{
		// Wrap the transport:
		Transport: httpsig.NewSignTransport(http.DefaultTransport,
			httpsig.WithHmacSha256("key1", []byte(secret))),
	}

	resp, err := client.Get("http://127.0.0.1:1234/")
	if err != nil {
		fmt.Println("got err: ", err)
		return
	}
	defer resp.Body.Close()

	fmt.Println(resp.Status)

	// Output:
	// 200 OK
}
