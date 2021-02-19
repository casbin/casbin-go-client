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

// GetRolesForUser gets the roles that a user has.
func (e *Enforcer) GetRolesForUser(ctx context.Context, name string) ([]string, error) {
	res, err := e.client.remoteClient.GetRolesForUser(ctx, &pb.UserRoleRequest{
		EnforcerHandler: e.handler,
		User:            name,
	})
	if err != nil {
		return nil, err
	}
	return res.Array, nil
}

// GetImplicitRolesForUser gets implicit roles that a user has.
// Compared to GetRolesForUser(), this function retrieves indirect roles besides direct roles.
// For example:
// g, alice, role:admin
// g, role:admin, role:user
//
// GetRolesForUser("alice") can only get: ["role:admin"].
// But GetImplicitRolesForUser("alice") will get: ["role:admin", "role:user"].
func (e *Enforcer) GetImplicitRolesForUser(ctx context.Context, name string, domain ...string) ([]string, error) {
	res, err := e.client.remoteClient.GetImplicitRolesForUser(ctx, &pb.UserRoleRequest{
		EnforcerHandler: e.handler,
		User:            name,
	})
	if err != nil {
		return nil, err
	}
	return res.Array, nil
}

// GetUsersForRole gets the users that has a role.
func (e *Enforcer) GetUsersForRole(ctx context.Context, name string) ([]string, error) {
	res, err := e.client.remoteClient.GetUsersForRole(ctx, &pb.UserRoleRequest{
		EnforcerHandler: e.handler,
		User:            name,
	})
	if err != nil {
		return nil, err
	}
	return res.Array, nil
}

// HasRoleForUser determines whether a user has a role.
func (e *Enforcer) HasRoleForUser(ctx context.Context, user, role string) (bool, error) {
	res, err := e.client.remoteClient.HasRoleForUser(ctx, &pb.UserRoleRequest{
		EnforcerHandler: e.handler,
		User:            user,
		Role:            role,
	})
	if err != nil {
		return false, err
	}
	return res.Res, nil
}

// AddRoleForUser adds a role for a user.
// Returns false if the user already has the role (aka not affected).
func (e *Enforcer) AddRoleForUser(ctx context.Context, user, role string) (bool, error) {
	res, err := e.client.remoteClient.AddRoleForUser(ctx, &pb.UserRoleRequest{
		EnforcerHandler: e.handler,
		User:            user,
		Role:            role,
	})
	if err != nil {
		return false, err
	}
	return res.Res, nil
}

// DeleteRoleForUser deletes a role for a user.
// Returns false if the user does not have the role (aka not affected).
func (e *Enforcer) DeleteRoleForUser(ctx context.Context, user, role string) (bool, error) {
	res, err := e.client.remoteClient.DeleteRoleForUser(ctx, &pb.UserRoleRequest{
		EnforcerHandler: e.handler,
		User:            user,
		Role:            role,
	})
	if err != nil {
		return false, err
	}
	return res.Res, nil
}

// DeleteRolesForUser deletes all roles for a user.
// Returns false if the user does not have any roles (aka not affected).
func (e *Enforcer) DeleteRolesForUser(ctx context.Context, user string) (bool, error) {
	res, err := e.client.remoteClient.DeleteRolesForUser(ctx, &pb.UserRoleRequest{
		EnforcerHandler: e.handler,
		User:            user,
	})
	if err != nil {
		return false, err
	}
	return res.Res, nil
}

// DeleteUser deletes a user.
// Returns false if the user does not exist (aka not affected).
func (e *Enforcer) DeleteUser(ctx context.Context, user string) (bool, error) {
	res, err := e.client.remoteClient.DeleteUser(ctx, &pb.UserRoleRequest{
		EnforcerHandler: e.handler,
		User:            user,
	})
	if err != nil {
		return false, err
	}
	return res.Res, nil
}

// DeleteRole deletes a role.
func (e *Enforcer) DeleteRole(ctx context.Context, role string) error {
	_, err := e.client.remoteClient.DeleteRole(ctx, &pb.UserRoleRequest{
		EnforcerHandler: e.handler,
		Role:            role,
	})
	return err
}

// GetPermissionsForUser gets permissions for a user or role.
func (e *Enforcer) GetPermissionsForUser(ctx context.Context, user string) ([][]string, error) {
	res, err := e.client.remoteClient.GetPermissionsForUser(ctx, &pb.PermissionRequest{
		EnforcerHandler: e.handler,
		User:            user,
	})
	if err != nil {
		return nil, err
	}
	return replyTo2DSlice(res), nil
}

// GetImplicitPermissionsForUser gets implicit permissions for a user or role.
// Compared to GetPermissionsForUser(), this function retrieves permissions for inherited roles.
// For example:
// p, admin, data1, read
// p, alice, data2, read
// g, alice, admin
//
// GetPermissionsForUser("alice") can only get: [["alice", "data2", "read"]].
// But GetImplicitPermissionsForUser("alice") will get: [["admin", "data1", "read"], ["alice", "data2", "read"]].
func (e *Enforcer) GetImplicitPermissionsForUser(ctx context.Context, user string, domain ...string) ([][]string, error) {
	res, err := e.client.remoteClient.GetImplicitPermissionsForUser(ctx, &pb.PermissionRequest{
		EnforcerHandler: e.handler,
		User:            user,
	})
	if err != nil {
		return nil, err
	}
	return replyTo2DSlice(res), nil
}

// DeletePermission deletes a permission.
// Returns false if the permission does not exist (aka not affected).
func (e *Enforcer) DeletePermission(ctx context.Context, permission ...string) (bool, error) {
	res, err := e.client.remoteClient.DeletePermission(ctx, &pb.PermissionRequest{
		EnforcerHandler: e.handler,
		Permissions:     permission,
	})
	if err != nil {
		return false, err
	}
	return res.Res, nil
}

// AddPermissionForUser adds a permission for a user or role.
// Returns false if the user or role already has the permission (aka not affected).
func (e *Enforcer) AddPermissionForUser(ctx context.Context, user string, permission ...string) (bool, error) {
	res, err := e.client.remoteClient.AddPermissionForUser(ctx, &pb.PermissionRequest{
		EnforcerHandler: e.handler,
		User:            user,
		Permissions:     permission,
	})
	if err != nil {
		return false, err
	}
	return res.Res, nil
}

// DeletePermissionForUser deletes a permission for a user or role.
// Returns false if the user or role does not have the permission (aka not affected).
func (e *Enforcer) DeletePermissionForUser(ctx context.Context, user string, permission ...string) (bool, error) {
	res, err := e.client.remoteClient.DeletePermissionForUser(ctx, &pb.PermissionRequest{
		EnforcerHandler: e.handler,
		User:            user,
		Permissions:     permission,
	})
	if err != nil {
		return false, err
	}
	return res.Res, nil
}

// DeletePermissionsForUser deletes permissions for a user or role.
// Returns false if the user or role does not have any permissions (aka not affected).
func (e *Enforcer) DeletePermissionsForUser(ctx context.Context, user string) (bool, error) {
	res, err := e.client.remoteClient.DeletePermissionsForUser(ctx, &pb.PermissionRequest{
		EnforcerHandler: e.handler,
		User:            user,
	})
	if err != nil {
		return false, err
	}
	return res.Res, nil
}

// HasPermissionForUser determines whether a user has a permission.
func (e *Enforcer) HasPermissionForUser(ctx context.Context, user string, permission ...string) (bool, error) {
	res, err := e.client.remoteClient.HasPermissionForUser(ctx, &pb.PermissionRequest{
		EnforcerHandler: e.handler,
		User:            user,
		Permissions:     permission,
	})
	if err != nil {
		return false, err
	}
	return res.Res, nil
}
