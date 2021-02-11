package main

import (
	"context"
	"fmt"
	"reflect"

	pb "github.com/casbin/casbin-server/proto"
	"github.com/casbin/casbin-server/server"
)

type Config struct {
	DriverName    string
	ConnectString string
	ModelText     string
	DbSpecified   bool
}

type Enforcer struct {
	handler int32
	client  *Client
}

func (c *Client) NewEnforcer(ctx context.Context, config Config) (*Enforcer, error) {
	var adapterHandler int32 = -1
	enforcer := &Enforcer{client: c}

	// Maybe it does not need NewAdapter.
	if config.DriverName != "" && config.ConnectString != "" {
		adapterReply, err := c.remoteClient.NewAdapter(ctx, &pb.NewAdapterRequest{
			DriverName:    config.DriverName,
			ConnectString: config.ConnectString,
			DbSpecified:   config.DbSpecified,
		})
		if err != nil {
			return enforcer, err
		}
		adapterHandler = adapterReply.Handler
	}

	e, err := c.remoteClient.NewEnforcer(ctx, &pb.NewEnforcerRequest{
		ModelText:     config.ModelText,
		AdapterHandle: adapterHandler,
	})
	if err != nil {
		return enforcer, err
	}
	enforcer.handler = e.Handler

	return enforcer, nil
}

func (e *Enforcer) Enforce(ctx context.Context, params ...interface{}) (bool, error) {
	var data []string
	for _, item := range params {
		var value string
		var err error
		if reflect.TypeOf(item).Kind() == reflect.Struct {
			value, err = server.MakeABAC(data)
			if err != nil {
				return false, err
			}
		} else {
			value = fmt.Sprintf("%v", item)
		}
		data = append(data, value)
	}

	res, err := e.client.remoteClient.Enforce(ctx, &pb.EnforceRequest{
		EnforcerHandler: e.handler,
		Params:          data,
	})
	return res.Res, err
}
