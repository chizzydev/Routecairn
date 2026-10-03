// Loopback-only, bounded behavior fixtures. Not an independently maintained corpus.
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var state = struct {
	sync.Mutex
	values map[string]string
}{values: make(map[string]string)}
var union = regexp.MustCompile(`(?i)UNION SELECT '([^']+)'`)
var crlf = regexp.MustCompile("\r\nX-RouteCairn-Proof: ([A-Za-z0-9_]+)")

func reply(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(value)
}
func route(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	if r.URL.Path == "/healthz" {
		reply(w, 200, map[string]any{"status": "ready"})
		return
	}
	p := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(p) < 3 {
		reply(w, 404, map[string]any{"error": "not_found"})
		return
	}
	family, control, variant := p[0], p[1], p[2]
	n, _ := strconv.Atoi(strings.TrimPrefix(variant, "v"))
	vulnerable, near := control == "vulnerable", control == "near-miss"
	q := r.URL.Query().Get("q")
	value := map[string]any{}
	switch family {
	case "object", "admin":
		if vulnerable {
			if family == "object" {
				value = map[string]any{"id": "tenant-a-object", "tenantId": "tenant-a", "variant": variant}
			} else {
				value = map[string]any{"privileged": true, "variant": variant}
			}
			reply(w, 200, value)
			return
		}
		if near {
			reply(w, 200, map[string]any{"kind": "public-help", "record": map[string]any{"id": "documentation-example", "privileged": false}})
			return
		}
		reply(w, []int{401, 403, 404}[n%3], map[string]any{"error": "forbidden"})
		return
	case "search":
		if vulnerable && strings.ContainsAny(q, "'\"") {
			reply(w, []int{400, 422, 500}[n%3], map[string]any{"error": "SQL syntax error near corpus canary"})
			return
		}
		value = map[string]any{"matches": []string{}, "variant": variant}
	case "sql-boolean":
		matches := []string{"fixture"}
		if vulnerable && strings.Contains(q, "1'='2") {
			matches = []string{}
		}
		value = map[string]any{"matches": matches}
	case "sql-union":
		matches := []string{}
		found := union.FindStringSubmatch(q)
		if vulnerable && len(found) > 1 {
			matches = append(matches, found[1])
		}
		value = map[string]any{"matches": matches}
	case "nosql":
		matches := []string{}
		var operator map[string]any
		_ = json.Unmarshal([]byte(q), &operator)
		if _, ok := operator["$ne"].(string); vulnerable && ok {
			matches = append(matches, "CORPUS_PRIVATE_DOCUMENT")
		}
		value = map[string]any{"matches": matches}
	case "crlf":
		found := crlf.FindStringSubmatch(q)
		if vulnerable && len(found) > 1 {
			w.Header().Set("x-routecairn-proof", found[1])
		}
		value = map[string]any{"accepted": true}
	case "template":
		if !vulnerable && strings.Contains(q, "{{") {
			reply(w, 422, map[string]any{"error": "literal_only"})
			return
		}
		if vulnerable {
			q = strings.ReplaceAll(q, "{{7*7}}", "49")
		}
		value = map[string]any{"rendered": q}
	case "traversal":
		if !vulnerable && strings.Contains(q, "../") {
			reply(w, 422, map[string]any{"error": "path_rejected"})
			return
		}
		content := "public file"
		if vulnerable && strings.Contains(q, "../") {
			content = "CORPUS_PRIVATE_FILE"
		}
		value = map[string]any{"content": content}
	case "redirect":
		location := "/home"
		if vulnerable {
			location = r.URL.Query().Get("next")
		}
		if near {
			location = "https://routecairn.invalid.example/safe"
		}
		w.Header().Set("Location", location)
		w.WriteHeader([]int{301, 302, 307, 308}[n%4])
		return
	case "auth":
		if len(p) < 4 {
			reply(w, 404, map[string]any{"error": "not_found"})
			return
		}
		if p[3] == "cleanup" && r.Method == "POST" {
			w.WriteHeader(204)
			return
		}
		if p[3] != "login" || r.Method != "POST" {
			reply(w, 404, map[string]any{"error": "not_found"})
			return
		}
		if r.ParseForm() != nil {
			reply(w, 400, map[string]any{"error": "invalid_request"})
			return
		}
		if vulnerable && r.Form.Get("username") != "known@benchmark.test" {
			reply(w, 404, map[string]any{"error": "account_not_found", "recovery": true})
			return
		}
		code := 401
		if near {
			code = 404
		}
		reply(w, code, map[string]any{"error": "invalid_credentials"})
		return
	case "second-order":
		if len(p) < 4 {
			reply(w, 404, map[string]any{"error": "not_found"})
			return
		}
		key := control + ":" + variant
		state.Lock()
		defer state.Unlock()
		switch p[3] {
		case "stage":
			if r.Method == "POST" {
				if r.ParseForm() != nil {
					reply(w, 400, map[string]any{"error": "invalid_request"})
					return
				}
				state.values[key] = r.Form.Get("payload")
				reply(w, 202, map[string]any{"accepted": true})
				return
			}
		case "render":
			if r.Method == "GET" {
				unsafe := vulnerable && state.values[key] != ""
				reply(w, 200, map[string]any{"safe": !unsafe})
				return
			}
		case "cleanup":
			if r.Method == "DELETE" {
				delete(state.values, key)
				w.WriteHeader(204)
				return
			}
		}
		reply(w, 404, map[string]any{"error": "not_found"})
		return
	default:
		reply(w, 404, map[string]any{"error": "not_found"})
		return
	}
	reply(w, 200, value)
}
func main() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	fmt.Printf("{\"port\":%d}\n", listener.Addr().(*net.TCPAddr).Port)
	server := http.Server{Handler: http.HandlerFunc(route), MaxHeaderBytes: 8192, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second}
	if err = server.Serve(listener); err != nil && err != http.ErrServerClosed {
		panic(err)
	}
}
