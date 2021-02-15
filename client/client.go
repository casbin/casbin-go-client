// Copyright 2018 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package client implements a Go client for casbin-server, and contains an implementation
// of an API similar to the casbin API.
package client

import (
	"context"

	pb "github.com/casbin/casbin-server/proto"
	"google.golang.org/grpc"
)

// Client is a wrapper around proto.CasbinClient, and can be used to create an Enforcer.
type Client struct {
	remoteClient pb.CasbinClient
}

// NewClient creates and returns a new client for casbin-server.
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
