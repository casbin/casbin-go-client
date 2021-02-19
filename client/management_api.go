// Copyright 2021 The casbin Authors. All Rights Reserved.
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

	pb "github.com/casbin/casbin-server/proto"
)

// AddPolicy adds an authorization rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (e *Enforcer) AddPolicy(ctx context.Context, params ...interface{}) (bool, error) {
	res, err := e.client.remoteClient.AddPolicy(ctx, &pb.PolicyRequest{
		EnforcerHandler: e.handler,
		PType:           "p",
		Params:          paramsToStrSlice(params),
	})
	if err != nil {
		return false, err
	}
	return res.Res, nil
}

// AddNamedPolicy adds an authorization rule to the current named policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (e *Enforcer) AddNamedPolicy(ctx context.Context, ptype string, params ...interface{}) (bool, error) {
	res, err := e.client.remoteClient.AddNamedPolicy(ctx, &pb.PolicyRequest{
		EnforcerHandler: e.handler,
		PType:           ptype,
		Params:          paramsToStrSlice(params),
	})
	if err != nil {
		return false, err
	}
	return res.Res, nil
}

// RemovePolicy removes an authorization rule from the current policy.
func (e *Enforcer) RemovePolicy(ctx context.Context, params ...interface{}) (bool, error) {
	res, err := e.client.remoteClient.RemovePolicy(ctx, &pb.PolicyRequest{
		EnforcerHandler: e.handler,
		PType:           "p",
		Params:          paramsToStrSlice(params),
	})
	if err != nil {
		return false, err
	}
	return res.Res, nil
}

// RemoveNamedPolicy removes an authorization rule from the current named policy.
func (e *Enforcer) RemoveNamedPolicy(ctx context.Context, ptype string, params ...interface{}) (bool, error) {
	res, err := e.client.remoteClient.RemoveNamedPolicy(ctx, &pb.PolicyRequest{
		EnforcerHandler: e.handler,
		PType:           ptype,
		Params:          paramsToStrSlice(params),
	})
	if err != nil {
		return false, err
	}
	return res.Res, nil
}

// RemoveFilteredPolicy removes an authorization rule from the current policy, field filters can be specified.
func (e *Enforcer) RemoveFilteredPolicy(ctx context.Context, fieldIndex int32, fieldValues ...string) (bool, error) {
	res, err := e.client.remoteClient.RemoveFilteredPolicy(ctx, &pb.FilteredPolicyRequest{
		EnforcerHandler: e.handler,
		PType:           "p",
		FieldIndex:      fieldIndex,
		FieldValues:     fieldValues,
	})
	if err != nil {
		return false, err
	}
	return res.Res, nil
}

// RemoveFilteredNamedPolicy removes an authorization rule from the current named policy, field filters can be specified.
func (e *Enforcer) RemoveFilteredNamedPolicy(ctx context.Context, ptype string, fieldIndex int32, fieldValues ...string) (bool, error) {
	res, err := e.client.remoteClient.RemoveFilteredNamedPolicy(ctx, &pb.FilteredPolicyRequest{
		EnforcerHandler: e.handler,
		PType:           ptype,
		FieldIndex:      fieldIndex,
		FieldValues:     fieldValues,
	})
	if err != nil {
		return false, err
	}
	return res.Res, nil
}

// GetPolicy gets all the authorization rules in the policy.
func (e *Enforcer) GetPolicy(ctx context.Context) ([][]string, error) {
	res, err := e.client.remoteClient.GetPolicy(ctx, &pb.EmptyRequest{Handler: e.handler})
	if err != nil {
		return nil, err
	}
	return replyTo2DSlice(res), nil
}

// GetNamedPolicy gets all the authorization rules in the named policy.
func (e *Enforcer) GetNamedPolicy(ctx context.Context, ptype string) ([][]string, error) {
	res, err := e.client.remoteClient.GetNamedPolicy(ctx, &pb.PolicyRequest{
		EnforcerHandler: e.handler,
		PType:           ptype,
	})
	if err != nil {
		return nil, err
	}
	return replyTo2DSlice(res), nil
}

// GetFilteredPolicy gets all the authorization rules in the policy, field filters can be specified.
func (e *Enforcer) GetFilteredPolicy(ctx context.Context, fieldIndex int32, fieldValues ...string) ([][]string, error) {
	res, err := e.client.remoteClient.GetFilteredPolicy(ctx, &pb.FilteredPolicyRequest{
		EnforcerHandler: e.handler,
		PType:           "p",
		FieldIndex:      fieldIndex,
		FieldValues:     fieldValues,
	})
	if err != nil {
		return nil, err
	}
	return replyTo2DSlice(res), nil
}

// GetFilteredNamedPolicy gets all the authorization rules in the named policy, field filters can be specified.
func (e *Enforcer) GetFilteredNamedPolicy(ctx context.Context, ptype string, fieldIndex int32, fieldValues ...string) ([][]string, error) {
	res, err := e.client.remoteClient.GetFilteredNamedPolicy(ctx, &pb.FilteredPolicyRequest{
		EnforcerHandler: e.handler,
		PType:           ptype,
		FieldIndex:      fieldIndex,
		FieldValues:     fieldValues,
	})
	if err != nil {
		return nil, err
	}
	return replyTo2DSlice(res), nil
}

// AddGroupingPolicy adds a role inheritance rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (e *Enforcer) AddGroupingPolicy(ctx context.Context, params ...interface{}) (bool, error) {
	res, err := e.client.remoteClient.AddGroupingPolicy(ctx, &pb.PolicyRequest{
		EnforcerHandler: e.handler,
		PType:           "g",
		Params:          paramsToStrSlice(params),
	})
	if err != nil {
		return false, err
	}
	return res.Res, nil
}

// AddNamedGroupingPolicy adds a named role inheritance rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (e *Enforcer) AddNamedGroupingPolicy(ctx context.Context, ptype string, params ...interface{}) (bool, error) {
	res, err := e.client.remoteClient.AddNamedGroupingPolicy(ctx, &pb.PolicyRequest{
		EnforcerHandler: e.handler,
		PType:           ptype,
		Params:          paramsToStrSlice(params),
	})
	if err != nil {
		return false, err
	}
	return res.Res, nil
}

// RemoveGroupingPolicy removes a role inheritance rule from the current policy.
func (e *Enforcer) RemoveGroupingPolicy(ctx context.Context, params ...interface{}) (bool, error) {
	res, err := e.client.remoteClient.RemoveGroupingPolicy(ctx, &pb.PolicyRequest{
		EnforcerHandler: e.handler,
		PType:           "g",
		Params:          paramsToStrSlice(params),
	})
	if err != nil {
		return false, err
	}
	return res.Res, nil
}

// RemoveNamedGroupingPolicy removes a role inheritance rule from the current named policy.
func (e *Enforcer) RemoveNamedGroupingPolicy(ctx context.Context, ptype string, params ...interface{}) (bool, error) {
	res, err := e.client.remoteClient.RemoveNamedGroupingPolicy(ctx, &pb.PolicyRequest{
		EnforcerHandler: e.handler,
		PType:           ptype,
		Params:          paramsToStrSlice(params),
	})
	if err != nil {
		return false, err
	}
	return res.Res, nil
}

// RemoveFilteredGroupingPolicy removes a role inheritance rule from the current policy, field filters can be specified.
func (e *Enforcer) RemoveFilteredGroupingPolicy(ctx context.Context, fieldIndex int32, fieldValues ...string) (bool, error) {
	res, err := e.client.remoteClient.RemoveFilteredGroupingPolicy(ctx, &pb.FilteredPolicyRequest{
		EnforcerHandler: e.handler,
		PType:           "g",
		FieldIndex:      fieldIndex,
		FieldValues:     fieldValues,
	})
	if err != nil {
		return false, err
	}
	return res.Res, nil
}

// RemoveFilteredNamedGroupingPolicy removes a role inheritance rule from the current named policy,
// field filters can be specified.
func (e *Enforcer) RemoveFilteredNamedGroupingPolicy(ctx context.Context, ptype string, fieldIndex int32, fieldValues ...string) (bool, error) {
	res, err := e.client.remoteClient.RemoveFilteredNamedGroupingPolicy(ctx, &pb.FilteredPolicyRequest{
		EnforcerHandler: e.handler,
		PType:           ptype,
		FieldIndex:      fieldIndex,
		FieldValues:     fieldValues,
	})
	if err != nil {
		return false, err
	}
	return res.Res, nil
}

// GetGroupingPolicy gets all the role inheritance rules in the policy.
func (e *Enforcer) GetGroupingPolicy(ctx context.Context) ([][]string, error) {
	res, err := e.client.remoteClient.GetGroupingPolicy(ctx, &pb.EmptyRequest{Handler: e.handler})
	if err != nil {
		return nil, err
	}
	return replyTo2DSlice(res), nil
}

// GetNamedGroupingPolicy gets all the role inheritance rules in the policy.
func (e *Enforcer) GetNamedGroupingPolicy(ctx context.Context, ptype string) ([][]string, error) {
	res, err := e.client.remoteClient.GetNamedGroupingPolicy(ctx, &pb.PolicyRequest{
		EnforcerHandler: e.handler,
		PType:           ptype,
	})
	if err != nil {
		return nil, err
	}
	return replyTo2DSlice(res), nil
}

// GetFilteredGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
func (e *Enforcer) GetFilteredGroupingPolicy(ctx context.Context, fieldIndex int32, fieldValues ...string) ([][]string, error) {
	res, err := e.client.remoteClient.GetFilteredGroupingPolicy(ctx, &pb.FilteredPolicyRequest{
		EnforcerHandler: e.handler,
		PType:           "g",
		FieldIndex:      fieldIndex,
		FieldValues:     fieldValues,
	})
	if err != nil {
		return nil, err
	}
	return replyTo2DSlice(res), nil
}

// GetFilteredNamedGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
func (e *Enforcer) GetFilteredNamedGroupingPolicy(ctx context.Context, ptype string, fieldIndex int32, fieldValues ...string) ([][]string, error) {
	res, err := e.client.remoteClient.GetFilteredNamedGroupingPolicy(ctx, &pb.FilteredPolicyRequest{
		EnforcerHandler: e.handler,
		PType:           ptype,
		FieldIndex:      fieldIndex,
		FieldValues:     fieldValues,
	})
	if err != nil {
		return nil, err
	}
	return replyTo2DSlice(res), nil
}

// GetAllSubjects gets the list of subjects that show up in the current policy.
func (e *Enforcer) GetAllSubjects(ctx context.Context) ([]string, error) {
	res, err := e.client.remoteClient.GetAllSubjects(ctx, &pb.EmptyRequest{Handler: e.handler})
	if err != nil {
		return nil, err
	}
	return res.Array, nil
}

// GetAllNamedSubjects gets the list of subjects that show up in the current named policy.
func (e *Enforcer) GetAllNamedSubjects(ctx context.Context, ptype string) ([]string, error) {
	res, err := e.client.remoteClient.GetAllNamedSubjects(ctx, &pb.SimpleGetRequest{
		EnforcerHandler: e.handler,
		PType:           ptype,
	})
	if err != nil {
		return nil, err
	}
	return res.Array, nil
}

// GetAllObjects gets the list of objects that show up in the current policy.
func (e *Enforcer) GetAllObjects(ctx context.Context) ([]string, error) {
	res, err := e.client.remoteClient.GetAllObjects(ctx, &pb.EmptyRequest{Handler: e.handler})
	if err != nil {
		return nil, err
	}
	return res.Array, nil
}

// GetAllNamedObjects gets the list of objects that show up in the current named policy.
func (e *Enforcer) GetAllNamedObjects(ctx context.Context, ptype string) ([]string, error) {
	res, err := e.client.remoteClient.GetAllNamedObjects(ctx, &pb.SimpleGetRequest{
		EnforcerHandler: e.handler,
		PType:           ptype,
	})
	if err != nil {
		return nil, err
	}
	return res.Array, nil
}

// GetAllActions gets the list of actions that show up in the current policy.
func (e *Enforcer) GetAllActions(ctx context.Context) ([]string, error) {
	res, err := e.client.remoteClient.GetAllActions(ctx, &pb.EmptyRequest{Handler: e.handler})
	if err != nil {
		return nil, err
	}
	return res.Array, nil
}

// GetAllNamedActions gets the list of actions that show up in the current named policy.
func (e *Enforcer) GetAllNamedActions(ctx context.Context, ptype string) ([]string, error) {
	res, err := e.client.remoteClient.GetAllNamedActions(ctx, &pb.SimpleGetRequest{
		EnforcerHandler: e.handler,
		PType:           ptype,
	})
	if err != nil {
		return nil, err
	}
	return res.Array, nil
}

// GetAllRoles gets the list of roles that show up in the current policy.
func (e *Enforcer) GetAllRoles(ctx context.Context) ([]string, error) {
	res, err := e.client.remoteClient.GetAllRoles(ctx, &pb.EmptyRequest{Handler: e.handler})
	if err != nil {
		return nil, err
	}
	return res.Array, nil
}

// GetAllNamedRoles gets the list of roles that show up in the current named policy.
func (e *Enforcer) GetAllNamedRoles(ctx context.Context, ptype string) ([]string, error) {
	res, err := e.client.remoteClient.GetAllNamedRoles(ctx, &pb.SimpleGetRequest{
		EnforcerHandler: e.handler,
		PType:           ptype,
	})
	if err != nil {
		return nil, err
	}
	return res.Array, nil
}

// HasPolicy determines whether an authorization rule exists.
func (e *Enforcer) HasPolicy(ctx context.Context, params ...interface{}) (bool, error) {
	res, err := e.client.remoteClient.HasPolicy(ctx, &pb.PolicyRequest{
		EnforcerHandler: e.handler,
		PType:           "p",
		Params:          paramsToStrSlice(params),
	})
	if err != nil {
		return false, err
	}
	return res.Res, nil
}

// HasNamedPolicy determines whether a named authorization rule exists.
func (e *Enforcer) HasNamedPolicy(ctx context.Context, ptype string, params ...interface{}) (bool, error) {
	res, err := e.client.remoteClient.HasNamedPolicy(ctx, &pb.PolicyRequest{
		EnforcerHandler: e.handler,
		PType:           ptype,
		Params:          paramsToStrSlice(params),
	})
	if err != nil {
		return false, err
	}
	return res.Res, nil
}

// HasGroupingPolicy determines whether a role inheritance rule exists.
func (e *Enforcer) HasGroupingPolicy(ctx context.Context, params ...interface{}) (bool, error) {
	res, err := e.client.remoteClient.HasGroupingPolicy(ctx, &pb.PolicyRequest{
		EnforcerHandler: e.handler,
		PType:           "g",
		Params:          paramsToStrSlice(params),
	})
	if err != nil {
		return false, err
	}
	return res.Res, nil
}

// HasNamedGroupingPolicy determines whether a named role inheritance rule exists.
func (e *Enforcer) HasNamedGroupingPolicy(ctx context.Context, ptype string, params ...interface{}) (bool, error) {
	res, err := e.client.remoteClient.HasNamedGroupingPolicy(ctx, &pb.PolicyRequest{
		EnforcerHandler: e.handler,
		PType:           ptype,
		Params:          paramsToStrSlice(params),
	})
	if err != nil {
		return false, err
	}
	return res.Res, nil
}

// paramsToStrSlice transforms params, which can either be one string slice or several seperate
// strings, into a slice of strings.
func paramsToStrSlice(params []interface{}) []string {
	if slice, ok := params[0].([]string); len(params) == 1 && ok {
		return slice
	}

	slice := make([]string, 0)
	for _, param := range params {
		slice = append(slice, param.(string))
	}
	return slice
}

// replyTo2DSlice transforms a Array2DReply to a 2d string slice.
func replyTo2DSlice(reply *pb.Array2DReply) [][]string {
	result := make([][]string, 0)
	for _, value := range reply.D2 {
		result = append(result, value.D1)
	}
	return result
}
