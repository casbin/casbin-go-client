package client

import (
	"context"
	"log"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/casbin/casbin/v2/util"
)

const (
	address = "127.0.0.1:50051"
)

var e *Enforcer

func testNewEnforcer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cc, err := NewClient(ctx, address, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("connot create client: %v", err)
	}

	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	e, err = cc.NewEnforcer(ctx, Config{ModelText: "", EnableAcceptJsonRequest: true})
	if err != nil {
		t.Fatalf("NewEnforcer() error: %v", err)
	}
}

func testGetPolicy(t *testing.T, myRes, res [][]string) {
	log.Print("Policy: ", myRes)

	if !util.Array2DEquals(res, myRes) {
		t.Error("Policy: ", myRes, ", supposed to be ", res)
	}
}

func testAddPolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := e.AddPolicy(ctx, "alice", "data1", "read")
	if err != nil {
		t.Fatalf("GetPolicy err: %v", err)
	}

	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	policies, err := e.GetPolicy(ctx)
	if err != nil {
		t.Fatalf("GetPolicy err: %v", err)
	}

	testGetPolicy(t, policies, [][]string{
		{"alice", "data1", "read"},
	})
}

func testRemovePolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := e.RemovePolicy(ctx, "alice", "data1", "read")
	if err != nil {
		t.Fatalf("Remove err: %v", err)
	}

	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	policies, err := e.GetPolicy(ctx)
	if err != nil {
		t.Fatalf("GetPolicy err: %v", err)
	}

	testGetPolicy(t, policies, [][]string{})
}

func testEnforce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := e.Enforce(ctx, "alice")
	if err == nil {
		t.Fatalf("Not found error: invalid request size")
	}

	res, err := e.Enforce(ctx, "alice", "data1", "read")
	if err != nil {
		t.Fatalf("Remove err: %v", err)
	}
	if !res {
		t.Fatalf("Matched policies")
	}
}

func TestEnforcer(t *testing.T) {
	testNewEnforcer(t)

	testAddPolicy(t)
	testEnforce(t)
	testRemovePolicy(t)
}
