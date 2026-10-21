package scim

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	defaultPageCount = 100
	maxPageCount     = 200
)

// AccountWriter is the account-manager surface the SCIM protocol layer needs.
// *server.DefaultAccountManager satisfies it.
type AccountWriter interface {
	SCIMAccountID(ctx context.Context) (string, error)
	SCIMUpsertUser(ctx context.Context, accountID, externalID, userName, email, displayName string, active bool) (*types.User, bool, error)
	SCIMGetUser(ctx context.Context, userID string) (*types.User, error)
	SCIMListUsers(ctx context.Context, accountID string) ([]*types.User, error)
	SCIMUpsertGroup(ctx context.Context, accountID, displayName string, memberUserIDs []string) (*types.Group, bool, error)
	SCIMUpdateGroup(ctx context.Context, accountID, groupID, displayName string, memberUserIDs []string) (*types.Group, error)
	SCIMGetGroup(ctx context.Context, accountID, groupID string) (*types.Group, []string, error)
	SCIMListGroups(ctx context.Context, accountID string) ([]*types.Group, error)
	SCIMDeleteGroup(ctx context.Context, accountID, groupID string) error
}

type handler struct {
	accountManager AccountWriter
}

// AddEndpoints registers the SCIM 2.0 provisioning endpoints on the /api
// router. When the config is absent or disabled nothing is registered and the
// paths 404. The endpoints authenticate with their own static bearer token, so
// callers must also register the corresponding auth-middleware bypass paths.
func AddEndpoints(accountManager AccountWriter, router *mux.Router, cfg *config.SCIMConfig) {
	if cfg == nil || !cfg.Enabled {
		return
	}

	h := &handler{accountManager: accountManager}

	scimRouter := router.PathPrefix("/scim/v2").Subrouter()
	scimRouter.Use(bearerTokenAuth(cfg.Token))

	scimRouter.HandleFunc("/ServiceProviderConfig", h.serviceProviderConfigItem)
	scimRouter.HandleFunc("/Users", h.usersCollection)
	scimRouter.HandleFunc("/Users/{id}", h.userItem)
	scimRouter.HandleFunc("/Groups", h.groupsCollection)
	scimRouter.HandleFunc("/Groups/{id}", h.groupItem)
}

func (h *handler) serviceProviderConfigItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.rejectMethod(w, r)
		return
	}
	writeSCIMJSON(w, http.StatusOK, serviceProviderConfig())
}

func (h *handler) usersCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listUsers(w, r)
	case http.MethodPost:
		h.upsertUser(w, r, "")
	default:
		h.rejectMethod(w, r)
	}
}

func (h *handler) userItem(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if id == "" {
		writeSCIMError(w, http.StatusBadRequest, "user id must be set")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getUser(w, r, id)
	case http.MethodPut:
		h.upsertUser(w, r, id)
	case http.MethodDelete:
		h.deleteUser(w, r, id)
	default:
		h.rejectMethod(w, r)
	}
}

func (h *handler) groupsCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listGroups(w, r)
	case http.MethodPost:
		h.createGroup(w, r)
	default:
		h.rejectMethod(w, r)
	}
}

func (h *handler) groupItem(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if id == "" {
		writeSCIMError(w, http.StatusBadRequest, "group id must be set")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getGroup(w, r, id)
	case http.MethodPut:
		h.putGroup(w, r, id)
	case http.MethodDelete:
		h.deleteGroup(w, r, id)
	default:
		h.rejectMethod(w, r)
	}
}

func (h *handler) rejectMethod(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPatch {
		writeSCIMError(w, http.StatusBadRequest, "PATCH is not supported")
		return
	}
	writeSCIMError(w, http.StatusBadRequest, "operation not supported")
}

func (h *handler) accountID(w http.ResponseWriter, r *http.Request) (string, bool) {
	accountID, err := h.accountManager.SCIMAccountID(r.Context())
	if err != nil {
		writeManagerError(w, err)
		return "", false
	}
	return accountID, true
}

func (h *handler) listUsers(w http.ResponseWriter, r *http.Request) {
	accountID, ok := h.accountID(w, r)
	if !ok {
		return
	}

	users, err := h.accountManager.SCIMListUsers(r.Context(), accountID)
	if err != nil {
		writeManagerError(w, err)
		return
	}

	startIndex, count := pageParams(r)
	page := paginate(users, startIndex, count)
	resources := make([]any, 0, len(page))
	for _, user := range page {
		resources = append(resources, toSCIMUser(user))
	}
	writeSCIMJSON(w, http.StatusOK, listResponse(len(users), startIndex, len(page), resources))
}

func (h *handler) getUser(w http.ResponseWriter, r *http.Request, userID string) {
	user, err := h.accountManager.SCIMGetUser(r.Context(), userID)
	if err != nil {
		writeManagerError(w, err)
		return
	}
	writeSCIMJSON(w, http.StatusOK, toSCIMUser(user))
}

func (h *handler) upsertUser(w http.ResponseWriter, r *http.Request, pathID string) {
	var req scimUserRequest
	if err := decodeSCIMRequest(r, &req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, err.Error())
		return
	}

	externalID := req.ExternalID
	if pathID != "" {
		externalID = pathID
	}
	if externalID == "" {
		externalID = req.UserName
	}
	if externalID == "" {
		writeSCIMError(w, http.StatusBadRequest, "externalId or userName must be set")
		return
	}

	active := true
	if req.Active != nil {
		active = *req.Active
	}

	email := ""
	if len(req.Emails) > 0 {
		email = req.Emails[0].Value
	}

	accountID, ok := h.accountID(w, r)
	if !ok {
		return
	}

	user, created, err := h.accountManager.SCIMUpsertUser(r.Context(), accountID, externalID, req.UserName, email, req.DisplayName, active)
	if err != nil {
		writeManagerError(w, err)
		return
	}

	statusCode := http.StatusOK
	if created {
		statusCode = http.StatusCreated
	}
	writeSCIMJSON(w, statusCode, toSCIMUser(user))
}

func (h *handler) deleteUser(w http.ResponseWriter, r *http.Request, userID string) {
	accountID, ok := h.accountID(w, r)
	if !ok {
		return
	}

	if _, err := h.accountManager.SCIMGetUser(r.Context(), userID); err != nil {
		writeManagerError(w, err)
		return
	}

	if _, _, err := h.accountManager.SCIMUpsertUser(r.Context(), accountID, userID, "", "", "", false); err != nil {
		writeManagerError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) listGroups(w http.ResponseWriter, r *http.Request) {
	accountID, ok := h.accountID(w, r)
	if !ok {
		return
	}

	groups, err := h.accountManager.SCIMListGroups(r.Context(), accountID)
	if err != nil {
		writeManagerError(w, err)
		return
	}

	usersByIDs, err := h.usersByIDs(r.Context(), accountID)
	if err != nil {
		writeManagerError(w, err)
		return
	}

	startIndex, count := pageParams(r)
	page := paginate(groups, startIndex, count)
	resources := make([]any, 0, len(page))
	for _, group := range page {
		resources = append(resources, groupWithMembers(group, usersByIDs, memberUserIDs(group, usersByIDs)))
	}
	writeSCIMJSON(w, http.StatusOK, listResponse(len(groups), startIndex, len(page), resources))
}

func (h *handler) createGroup(w http.ResponseWriter, r *http.Request) {
	var req scimGroupRequest
	if err := decodeSCIMRequest(r, &req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.DisplayName == "" {
		writeSCIMError(w, http.StatusBadRequest, "displayName must be set")
		return
	}

	accountID, ok := h.accountID(w, r)
	if !ok {
		return
	}

	group, created, err := h.accountManager.SCIMUpsertGroup(r.Context(), accountID, req.DisplayName, req.memberUserIDs())
	if err != nil {
		writeManagerError(w, err)
		return
	}

	usersByIDs, err := h.usersByIDs(r.Context(), accountID)
	if err != nil {
		writeManagerError(w, err)
		return
	}

	statusCode := http.StatusOK
	if created {
		statusCode = http.StatusCreated
	}
	writeSCIMJSON(w, statusCode, groupWithMembers(group, usersByIDs, memberUserIDs(group, usersByIDs)))
}

func (h *handler) getGroup(w http.ResponseWriter, r *http.Request, groupID string) {
	accountID, ok := h.accountID(w, r)
	if !ok {
		return
	}

	group, memberIDs, err := h.accountManager.SCIMGetGroup(r.Context(), accountID, groupID)
	if err != nil {
		writeManagerError(w, err)
		return
	}

	usersByIDs, err := h.usersByIDs(r.Context(), accountID)
	if err != nil {
		writeManagerError(w, err)
		return
	}

	memberUsers := make([]*types.User, 0, len(memberIDs))
	for _, id := range memberIDs {
		if user, ok := usersByIDs[id]; ok {
			memberUsers = append(memberUsers, user)
		}
	}
	writeSCIMJSON(w, http.StatusOK, toSCIMGroup(group, memberUsers))
}

func (h *handler) putGroup(w http.ResponseWriter, r *http.Request, groupID string) {
	var req scimGroupRequest
	if err := decodeSCIMRequest(r, &req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, err.Error())
		return
	}

	accountID, ok := h.accountID(w, r)
	if !ok {
		return
	}

	if _, err := h.accountManager.SCIMUpdateGroup(r.Context(), accountID, groupID, req.DisplayName, req.memberUserIDs()); err != nil {
		writeManagerError(w, err)
		return
	}

	h.getGroup(w, r, groupID)
}

func (h *handler) deleteGroup(w http.ResponseWriter, r *http.Request, groupID string) {
	accountID, ok := h.accountID(w, r)
	if !ok {
		return
	}

	if err := h.accountManager.SCIMDeleteGroup(r.Context(), accountID, groupID); err != nil {
		writeManagerError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) usersByIDs(ctx context.Context, accountID string) (map[string]*types.User, error) {
	users, err := h.accountManager.SCIMListUsers(ctx, accountID)
	if err != nil {
		return nil, err
	}
	usersByIDs := make(map[string]*types.User, len(users))
	for _, user := range users {
		usersByIDs[user.Id] = user
	}
	return usersByIDs, nil
}

// memberUserIDs lists the group's members as user IDs, derived from the users'
// auto-groups so group listings don't depend on peer-based membership.
func memberUserIDs(group *types.Group, usersByIDs map[string]*types.User) []string {
	var memberIDs []string
	for _, user := range usersByIDs {
		for _, autoGroupID := range user.AutoGroups {
			if autoGroupID == group.ID {
				memberIDs = append(memberIDs, user.Id)
				break
			}
		}
	}
	return memberIDs
}

func groupWithMembers(group *types.Group, usersByIDs map[string]*types.User, memberIDs []string) scimGroup {
	memberUsers := make([]*types.User, 0, len(memberIDs))
	for _, id := range memberIDs {
		if user, ok := usersByIDs[id]; ok {
			memberUsers = append(memberUsers, user)
		}
	}
	return toSCIMGroup(group, memberUsers)
}

func listResponse(totalResults, startIndex, itemsPerPage int, resources []any) scimListResponse {
	return scimListResponse{
		Schemas:      []string{schemaListResponse},
		TotalResults: totalResults,
		StartIndex:   startIndex,
		ItemsPerPage: itemsPerPage,
		Resources:    resources,
	}
}

func pageParams(r *http.Request) (startIndex, count int) {
	startIndex, err := strconv.Atoi(r.URL.Query().Get("startIndex"))
	if err != nil || startIndex < 1 {
		startIndex = 1
	}

	count, err = strconv.Atoi(r.URL.Query().Get("count"))
	if err != nil || count < 1 {
		count = defaultPageCount
	}
	if count > maxPageCount {
		count = maxPageCount
	}
	return startIndex, count
}

func paginate[T any](items []T, startIndex, count int) []T {
	offset := startIndex - 1
	if offset >= len(items) {
		return nil
	}
	end := offset + count
	if end > len(items) {
		end = len(items)
	}
	return items[offset:end]
}

func bearerTokenAuth(token string) func(http.Handler) http.Handler {
	tokenHash := sha256.Sum256([]byte(token))
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			const prefix = "Bearer "
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, prefix) {
				unauthorized(w, "missing bearer token")
				return
			}
			providedHash := sha256.Sum256([]byte(strings.TrimPrefix(authHeader, prefix)))
			if subtle.ConstantTimeCompare(tokenHash[:], providedHash[:]) != 1 {
				unauthorized(w, "invalid bearer token")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func unauthorized(w http.ResponseWriter, detail string) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeSCIMError(w, http.StatusUnauthorized, detail)
}

// writeManagerError maps account-manager errors onto SCIM error responses.
func writeManagerError(w http.ResponseWriter, err error) {
	var linkErr *server.GroupLinkError
	if errors.As(err, &linkErr) {
		writeSCIMError(w, http.StatusConflict, err.Error())
		return
	}
	if errors.Is(err, server.ErrSCIMGroupConflict) {
		writeSCIMError(w, http.StatusConflict, err.Error())
		return
	}

	if s, ok := status.FromError(err); ok {
		switch s.Type() {
		case status.NotFound:
			writeSCIMError(w, http.StatusNotFound, err.Error())
			return
		case status.AlreadyExists:
			writeSCIMError(w, http.StatusConflict, err.Error())
			return
		case status.PermissionDenied:
			writeSCIMError(w, http.StatusForbidden, err.Error())
			return
		case status.InvalidArgument:
			writeSCIMError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	writeSCIMError(w, http.StatusInternalServerError, err.Error())
}
