package main

import (
	"context"

	pb "github.com/casbin/casbin-server/proto"
	"google.golang.org/grpc"
)

type Client struct {
	remoteClient pb.CasbinClient
	ctx          context.Context
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
		ctx:          ctx,
	}, nil
}
