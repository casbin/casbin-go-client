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

package client

import (
	"context"
	"fmt"
	"reflect"

	pb "github.com/casbin/casbin-server/proto"
	"github.com/casbin/casbin-server/server"
)

// Config contains data needed to create an enforcer.
type Config struct {
	DriverName    string
	ConnectString string
	ModelText     string
	DbSpecified   bool
}

// Enforcer is the main interface for authorization enforcement and policy management.
type Enforcer struct {
	handler int32
	client  *Client
}

// NewEnforcer creates an enforcer via file or DB.
// File:
// e := casbin.NewEnforcer("path/to/basic_model.conf", "path/to/basic_policy.csv")
// MySQL DB:
// a := mysqladapter.NewDBAdapter("mysql", "mysql_username:mysql_password@tcp(127.0.0.1:3306)/")
// e := casbin.NewEnforcer("path/to/basic_model.conf", a)
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

// Enforce decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
func (e *Enforcer) Enforce(ctx context.Context, params ...interface{}) (bool, error) {
	var data []string
	for _, item := range params {
		var value string
		var err error
		if reflect.TypeOf(item).Kind() == reflect.Struct {
			value, err = server.MakeABAC(item)
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
	if err != nil {
		return false, err
	}
	return res.Res, err
}

// LoadPolicy reloads the policy from file/database.
func (e *Enforcer) LoadPolicy(ctx context.Context) error {
	_, err := e.client.remoteClient.LoadPolicy(ctx, &pb.EmptyRequest{Handler: e.handler})
	return err
}

// SavePolicy saves the current policy (usually after changed with Casbin API) back to file/database.
func (e *Enforcer) SavePolicy(ctx context.Context) error {
	_, err := e.client.remoteClient.SavePolicy(ctx, &pb.EmptyRequest{Handler: e.handler})
	return err
}
