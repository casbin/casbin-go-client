// Package client implements a Go client for casbin-server, and contains an implementation
// of an API similar to the casbin API.
package client

import (
	"context"

	pb "github.com/casbin/casbin-server/proto"
	"google.golang.org/grpc"
)

type Client struct {
	remoteClient pb.CasbinClient
}

func NewClient(ctx context.Context, address string, opts ...grpc.DialOption) (*Client, error) {
	// Set up a connection to the server.
	conn, err := grpc.Dial(address, opts...)
	if err != nil {
		return nil, err
	}
	c := pb.NewCasbinClient(conn)

	return &Client{
		remoteClient: c,
	}, nil
}
