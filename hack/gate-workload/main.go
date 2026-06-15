package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })
	go http.ListenAndServe(":8080", nil)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
}
