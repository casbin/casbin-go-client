Go client for Casbin Server
====
[![Go Report Card](https://goreportcard.com/badge/github.com/casbin/casbin-go-client)](https://goreportcard.com/report/github.com/casbin/casbin-go-client)
[![GitHub Actions](https://github.com/casbin/casbin-go-client/actions/workflows/ci.yml/badge.svg)](https://github.com/casbin/casbin-go-client/actions)
[![Go Reference](https://pkg.go.dev/badge/github.com/casbin/casbin-go-client.svg)](https://pkg.go.dev/github.com/casbin/casbin-go-client)
[![Release](https://img.shields.io/github/release/casbin/casbin-go-client.svg)](https://github.com/casbin/casbin-go-client/releases/latest)
[![Discord](https://img.shields.io/discord/1022748306096537660?logo=discord&label=discord&color=5865F2)](https://discord.gg/S5UjpzGZjN)
[![Sourcegraph](https://sourcegraph.com/github.com/casbin/casbin-go-client/-/badge.svg)](https://sourcegraph.com/github.com/casbin/casbin-go-client?badge)

``casbin-go-client`` is Golang's client for [Casbin-Server](https://github.com/casbin/casbin-server). ``Casbin-Server`` is the ``Access Control as a Service (ACaaS)`` solution based on [Casbin](https://github.com/casbin/casbin).

## Installation

```bash
go mod init your-project
go mod tidy
```

## Quick Start

First, start the casbin-server:

```bash
# Install casbin-server
go install github.com/casbin/casbin-server@latest

# Start the server
casbin-server
```

Then use the client:

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/casbin/casbin-go-client/client"
    "google.golang.org/grpc"
)

func main() {
    // Create client with insecure connection
    c, err := client.NewClient(context.Background(), "127.0.0.1:50051", grpc.WithInsecure())
    if err != nil {
        log.Fatal(err)
    }

    // Define RBAC model
    modelText := `
        [request_definition]
        r = sub, obj, act

        [policy_definition]
        p = sub, obj, act

        [role_definition]
        g = _, _

        [policy_effect]
        e = some(where (p.eft == allow))

        [matchers]
        m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
    `

    // Create enforcer
    enforcer, err := c.NewEnforcer(context.Background(), client.Config{
        ModelText: modelText,
    })
    if err != nil {
        log.Fatal(err)
    }

    // Add policy
    enforcer.AddPolicy(context.Background(), "alice", "data1", "read")

    // Check permission
    allowed, err := enforcer.Enforce(context.Background(), "alice", "data1", "read")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("alice can read data1: %v\n", allowed) // true
}
```

## License

This project is under Apache 2.0 License. See the [LICENSE](LICENSE) file for the full license text.
