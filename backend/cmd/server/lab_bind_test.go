package main

import "testing"

// P0 Lab transport exposure guard: 25 explicit address/port threat cases.
// No sockets are opened; the allowlist is numeric loopback only. Production
// endpoint traffic must use a separately authenticated agent mTLS listener.
func TestLabListenAddrSecurityMatrix(t *testing.T) {
    cases := []struct {
        name string
        input string
        want string
        allowed bool
    }{
        {name: "default-loopback", input: "", want: "127.0.0.1:8080", allowed: true},
        {name: "ipv4-default", input: "127.0.0.1:8080", want: "127.0.0.1:8080", allowed: true},
        {name: "ipv4-ephemeral-number", input: "127.0.0.1:1", want: "127.0.0.1:1", allowed: true},
        {name: "ipv4-other-loopback", input: "127.0.0.2:9090", want: "127.0.0.2:9090", allowed: true},
        {name: "ipv6-loopback", input: "[::1]:8080", want: "[::1]:8080", allowed: true},
        {name: "ipv6-https-port", input: "[::1]:443", want: "[::1]:443", allowed: true},
        {name: "ipv4-wildcard", input: "0.0.0.0:8080", want: "", allowed: false},
        {name: "ipv6-wildcard", input: "[::]:8080", want: "", allowed: false},
        {name: "public-documentation-ip", input: "203.0.113.10:8080", want: "", allowed: false},
        {name: "private-lan-ip", input: "10.1.2.3:8080", want: "", allowed: false},
        {name: "link-local-ip", input: "169.254.12.2:8080", want: "", allowed: false},
        {name: "non-numeric-localhost", input: "localhost:8080", want: "", allowed: false},
        {name: "arbitrary-dns", input: "lab.example:8080", want: "", allowed: false},
        {name: "empty-host", input: ":8080", want: "", allowed: false},
        {name: "missing-port", input: "127.0.0.1", want: "", allowed: false},
        {name: "zero-port", input: "127.0.0.1:0", want: "", allowed: false},
        {name: "negative-port", input: "127.0.0.1:-1", want: "", allowed: false},
        {name: "port-overflow", input: "127.0.0.1:65536", want: "", allowed: false},
        {name: "invalid-port", input: "127.0.0.1:notaport", want: "", allowed: false},
        {name: "stray-colon", input: "127.0.0.1:8080:99", want: "", allowed: false},
        {name: "url-instead-of-address", input: "https://127.0.0.1:8080", want: "", allowed: false},
        {name: "leading-whitespace", input: " 127.0.0.1:8080", want: "", allowed: false},
        {name: "unbracketed-ipv6", input: "::1:8080", want: "", allowed: false},
        {name: "ipv6-zone", input: "[::1%eth0]:8080", want: "", allowed: false},
        {name: "wildcard-host", input: "*:8080", want: "", allowed: false},
    }
    if len(cases) != 25 { t.Fatalf("test matrix shrank to %d cases", len(cases)) }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            got, err := labListenAddr(tc.input)
            if tc.allowed {
                if err != nil || got != tc.want {
                    t.Fatalf("loopback listener %q: got %q, err %v; want %q", tc.input, got, err, tc.want)
                }
                return
            }
            if err == nil || got != "" {
                t.Fatalf("unsafe lab listener %q was accepted as %q, err %v", tc.input, got, err)
            }
        })
    }
}
