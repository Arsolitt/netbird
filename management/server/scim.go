package server

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/affectedpeers"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/util"
	"github.com/netbirdio/netbird/shared/management/integration_reference"
	"github.com/netbirdio/netbird/shared/management/status"
)

const scimIntegrationType = "scim"

// ErrSCIMGroupConflict signals that an API-issued group already holds the name a
// SCIM request wants to manage; the admin must rename or convert it first.
var ErrSCIMGroupConflict = errors.New("group with the same name was issued via the API")

// SCIMAccountID returns the account ID of the deployment. SCIM is only served
// when exactly one account exists, so the value is resolved once and cached.
func (am *DefaultAccountManager) SCIMAccountID(ctx context.Context) (string, error) {
	am.scimAccountOnce.Do(func() {
		accounts := am.Store.GetAllAccounts(ctx)
		if len(accounts) != 1 {
			am.scimAccountErr = fmt.Errorf("SCIM requires a single-account deployment, found %d accounts", len(accounts))
			return
		}
		am.scimAccountID = accounts[0].Id
	})
	return am.scimAccountID, am.scimAccountErr
}

// SCIMUpsertUser creates the user pre-login or reconciles it when it already
// exists. The external ID becomes the NetBird user ID, which a later JWT login
// matches as its subject. SCIM is the source of truth for in-scope users, so
// every call reconciles the blocked state from the active flag.
func (am *DefaultAccountManager) SCIMUpsertUser(ctx context.Context, accountID, externalID, userName, email, displayName string, active bool) (*types.User, bool, error) {
	if displayName == "" {
		displayName = userName
	}

	existing, err := am.GetUserByID(ctx, externalID)
	if err != nil {
		if s, ok := status.FromError(err); !ok || s.Type() != status.NotFound {
			return nil, false, err
		}

		created := &types.User{
			Id:                   externalID,
			AccountID:            accountID,
			Role:                 types.UserRoleUser,
			Issued:               types.UserIssuedIntegration,
			IntegrationReference: integration_reference.IntegrationReference{IntegrationType: scimIntegrationType},
			Name:                 displayName,
			Email:                email,
			Blocked:              !active,
		}
		if _, err := am.SaveOrAddUser(ctx, accountID, activity.SystemInitiator, created, true); err != nil {
			return nil, false, err
		}
		return created, true, nil
	}

	if existing.AccountID != accountID {
		return nil, false, status.Errorf(status.InvalidArgument, "user account ID mismatch")
	}

	update := existing.Copy()
	if displayName != "" {
		update.Name = displayName
	}
	if email != "" {
		update.Email = email
	}
	update.Blocked = !active
	if _, err := am.SaveUser(ctx, accountID, activity.SystemInitiator, update); err != nil {
		return nil, false, err
	}
	return update, false, nil
}

// SCIMGetUser returns the user with the given NetBird user ID.
func (am *DefaultAccountManager) SCIMGetUser(ctx context.Context, userID string) (*types.User, error) {
	return am.GetUserByID(ctx, userID)
}

// SCIMListUsers returns all users of the account.
func (am *DefaultAccountManager) SCIMListUsers(ctx context.Context, accountID string) ([]*types.User, error) {
	return am.Store.GetAccountUsers(ctx, store.LockingStrengthNone, accountID)
}

// scimSetGroupMembers reconciles the group's membership to exactly the given
// user IDs by adding and removing the group from the users' auto-groups. The
// system initiator skips the regular user-update gate, so members are validated
// here: every ID must resolve to a user and the group must not be the All group.
func (am *DefaultAccountManager) scimSetGroupMembers(ctx context.Context, accountID, groupID string, memberUserIDs []string) error {
	group, err := am.Store.GetGroupByID(ctx, store.LockingStrengthNone, accountID, groupID)
	if err != nil {
		return err
	}
	if group.IsGroupAll() {
		return status.Errorf(status.InvalidArgument, "can't modify the All group membership via SCIM")
	}

	memberSet := make(map[string]struct{}, len(memberUserIDs))
	for _, userID := range memberUserIDs {
		if _, err := am.GetUserByID(ctx, userID); err != nil {
			return status.Errorf(status.InvalidArgument, "SCIM group member %s not found", userID)
		}
		memberSet[userID] = struct{}{}
	}

	users, err := am.Store.GetAccountUsers(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return err
	}

	var updates []*types.User
	for _, user := range users {
		isMember := slices.Contains(user.AutoGroups, groupID)
		_, wantMember := memberSet[user.Id]
		if isMember == wantMember {
			continue
		}

		update := user.Copy()
		if wantMember {
			update.AutoGroups = append(update.AutoGroups, groupID)
		} else {
			update.AutoGroups = util.Difference(user.AutoGroups, []string{groupID})
		}
		updates = append(updates, update)
	}

	if len(updates) == 0 {
		return nil
	}

	_, err = am.SaveOrAddUsers(ctx, accountID, activity.SystemInitiator, updates, false)
	return err
}

// SCIMUpsertGroup creates the group, adopts a same-name jwt-issued group in
// place (ID preserved so policies keep working), or reconciles the members of an
// existing integration-issued group. A same-name api-issued group is refused
// with ErrSCIMGroupConflict. The second return value reports a fresh creation.
func (am *DefaultAccountManager) SCIMUpsertGroup(ctx context.Context, accountID, displayName string, memberUserIDs []string) (*types.Group, bool, error) {
	existing, err := am.GetGroupByName(ctx, displayName, accountID, activity.SystemInitiator)
	if err != nil {
		if s, ok := status.FromError(err); !ok || s.Type() != status.NotFound {
			return nil, false, err
		}
	}

	if existing == nil {
		created := &types.Group{
			ID:                   xid.New().String(),
			AccountID:            accountID,
			Name:                 displayName,
			Issued:               types.GroupIssuedIntegration,
			IntegrationReference: integration_reference.IntegrationReference{IntegrationType: scimIntegrationType},
		}
		if err := am.CreateGroup(ctx, accountID, activity.SystemInitiator, created); err != nil {
			return nil, false, err
		}
		if err := am.scimSetGroupMembers(ctx, accountID, created.ID, memberUserIDs); err != nil {
			return nil, false, err
		}
		return created, true, nil
	}

	switch existing.Issued {
	case types.GroupIssuedAPI:
		return nil, false, fmt.Errorf("%w: rename or convert group %s first", ErrSCIMGroupConflict, displayName)
	case types.GroupIssuedJWT:
		adopted := existing.Copy()
		adopted.Issued = types.GroupIssuedIntegration
		adopted.IntegrationReference = integration_reference.IntegrationReference{IntegrationType: scimIntegrationType}
		if err := am.UpdateGroup(ctx, accountID, activity.SystemInitiator, adopted); err != nil {
			return nil, false, err
		}
		log.WithContext(ctx).Infof("SCIM: adopted jwt-issued group %s (%s)", adopted.Name, adopted.ID)
		if err := am.scimSetGroupMembers(ctx, accountID, adopted.ID, memberUserIDs); err != nil {
			return nil, false, err
		}
		return adopted, false, nil
	case types.GroupIssuedIntegration:
		if err := am.scimSetGroupMembers(ctx, accountID, existing.ID, memberUserIDs); err != nil {
			return nil, false, err
		}
		return existing, false, nil
	default:
		return nil, false, status.Errorf(status.Internal, "unknown group issued type %q", existing.Issued)
	}
}

// SCIMUpdateGroup renames an integration-issued group and reconciles its
// members. The rename is refused when a different group already holds the name.
func (am *DefaultAccountManager) SCIMUpdateGroup(ctx context.Context, accountID, groupID, displayName string, memberUserIDs []string) (*types.Group, error) {
	group, err := am.Store.GetGroupByID(ctx, store.LockingStrengthNone, accountID, groupID)
	if err != nil {
		return nil, err
	}
	if group.Issued != types.GroupIssuedIntegration {
		return nil, status.Errorf(status.PermissionDenied, "cannot modify non-integration group via SCIM")
	}

	updated := group.Copy()
	if displayName != "" && displayName != group.Name {
		nameHolder, err := am.GetGroupByName(ctx, displayName, accountID, activity.SystemInitiator)
		if err != nil {
			if s, ok := status.FromError(err); !ok || s.Type() != status.NotFound {
				return nil, err
			}
		}
		if nameHolder != nil && nameHolder.ID != group.ID {
			return nil, status.Errorf(status.AlreadyExists, "group with name %s already exists", displayName)
		}
		updated.Name = displayName
		if err := am.UpdateGroup(ctx, accountID, activity.SystemInitiator, updated); err != nil {
			return nil, err
		}
	}

	if err := am.scimSetGroupMembers(ctx, accountID, groupID, memberUserIDs); err != nil {
		return nil, err
	}
	return updated, nil
}

// SCIMGetGroup returns the group and the IDs of the users whose auto-groups
// contain it.
func (am *DefaultAccountManager) SCIMGetGroup(ctx context.Context, accountID, groupID string) (*types.Group, []string, error) {
	group, err := am.Store.GetGroupByID(ctx, store.LockingStrengthNone, accountID, groupID)
	if err != nil {
		return nil, nil, err
	}

	users, err := am.Store.GetAccountUsers(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, nil, err
	}

	var memberUserIDs []string
	for _, user := range users {
		if slices.Contains(user.AutoGroups, groupID) {
			memberUserIDs = append(memberUserIDs, user.Id)
		}
	}
	return group, memberUserIDs, nil
}

// SCIMListGroups returns all groups of the account.
func (am *DefaultAccountManager) SCIMListGroups(ctx context.Context, accountID string) ([]*types.Group, error) {
	return am.GetAllGroups(ctx, accountID, activity.SystemInitiator)
}

// SCIMDeleteGroup removes an integration-issued group. Membership is stripped
// first so the user-link check passes; a group still referenced by a policy or
// any other entity fails with a *GroupLinkError until that link is removed.
func (am *DefaultAccountManager) SCIMDeleteGroup(ctx context.Context, accountID, groupID string) error {
	group, err := am.Store.GetGroupByID(ctx, store.LockingStrengthNone, accountID, groupID)
	if err != nil {
		return err
	}
	if group.Issued != types.GroupIssuedIntegration {
		return status.Errorf(status.PermissionDenied, "cannot delete non-integration group via SCIM")
	}

	if err := am.scimSetGroupMembers(ctx, accountID, groupID, nil); err != nil {
		return err
	}

	extraSettings, err := am.settingsManager.GetExtraSettings(ctx, accountID)
	if err != nil {
		return err
	}

	var snap *affectedpeers.Snapshot
	change := affectedpeers.Change{ChangedGroupIDs: []string{groupID}}

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		if err := validateDeleteGroupLinks(ctx, transaction, group, extraSettings.FlowGroups); err != nil {
			return err
		}
		if snap, err = affectedpeers.Load(ctx, transaction, accountID, change); err != nil {
			return err
		}
		if err := transaction.DeleteGroups(ctx, accountID, []string{groupID}); err != nil {
			return err
		}
		if err := am.reconcileIPv6ForGroupChanges(ctx, transaction, accountID, []string{groupID}); err != nil {
			return err
		}
		return transaction.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		return err
	}

	am.StoreEvent(ctx, activity.SystemInitiator, group.ID, accountID, activity.GroupDeleted, group.EventMeta())
	am.ExpandAndUpdateAffected(ctx, accountID, snap, change)

	return nil
}
