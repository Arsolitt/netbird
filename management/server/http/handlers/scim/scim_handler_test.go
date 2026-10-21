package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

const testToken = "unit-scim-token"

type stubAccountWriter struct {
	accountID       string
	users           map[string]*types.User
	groups          map[string]*types.Group
	upsertUserCalls int
}

func newStubWriter() *stubAccountWriter {
	return &stubAccountWriter{
		accountID: "acc-1",
		users: map[string]*types.User{
			"user-a": {Id: "user-a", AccountID: "acc-1", Name: "User A", Email: "a@example.com", AutoGroups: []string{"grp-old"}},
			"user-b": {Id: "user-b", AccountID: "acc-1", Name: "User B"},
			"user-c": {Id: "user-c", AccountID: "acc-1", Name: "User C"},
			"user-d": {Id: "user-d", AccountID: "acc-1", Name: "User D"},
			"user-e": {Id: "user-e", AccountID: "acc-1", Name: "User E"},
		},
		groups: map[string]*types.Group{
			"grp-jwt": {ID: "grp-jwt", AccountID: "acc-1", Name: "from-jwt", Issued: types.GroupIssuedJWT},
			"grp-api": {ID: "grp-api", AccountID: "acc-1", Name: "from-api", Issued: types.GroupIssuedAPI},
			"grp-int": {ID: "grp-int", AccountID: "acc-1", Name: "from-integration", Issued: types.GroupIssuedIntegration},
		},
	}
}

func (s *stubAccountWriter) SCIMAccountID(_ context.Context) (string, error) {
	return s.accountID, nil
}

func (s *stubAccountWriter) SCIMUpsertUser(_ context.Context, _, externalID, _, email, displayName string, active bool) (*types.User, bool, error) {
	s.upsertUserCalls++
	existing, ok := s.users[externalID]
	if !ok {
		created := &types.User{
			Id:        externalID,
			AccountID: s.accountID,
			Name:      displayName,
			Email:     email,
			Blocked:   !active,
		}
		s.users[externalID] = created
		return created, true, nil
	}
	if displayName != "" {
		existing.Name = displayName
	}
	if email != "" {
		existing.Email = email
	}
	existing.Blocked = !active
	return existing, false, nil
}

func (s *stubAccountWriter) SCIMGetUser(_ context.Context, userID string) (*types.User, error) {
	user, ok := s.users[userID]
	if !ok {
		return nil, status.NewUserNotFoundError(userID)
	}
	return user, nil
}

func (s *stubAccountWriter) SCIMListUsers(_ context.Context, _ string) ([]*types.User, error) {
	users := make([]*types.User, 0, len(s.users))
	for _, id := range []string{"user-a", "user-b", "user-c", "user-d", "user-e"} {
		users = append(users, s.users[id])
	}
	return users, nil
}

func (s *stubAccountWriter) SCIMUpsertGroup(_ context.Context, _, displayName string, memberUserIDs []string) (*types.Group, bool, error) {
	for _, group := range s.groups {
		if group.Name != displayName {
			continue
		}
		switch group.Issued {
		case types.GroupIssuedAPI:
			return nil, false, fmt.Errorf("%w: rename or convert group %s first", server.ErrSCIMGroupConflict, displayName)
		case types.GroupIssuedJWT:
			group.Issued = types.GroupIssuedIntegration
			s.applyMembers(group, memberUserIDs)
			return group, false, nil
		case types.GroupIssuedIntegration:
			s.applyMembers(group, memberUserIDs)
			return group, false, nil
		}
	}
	created := &types.Group{ID: "grp-new-" + displayName, AccountID: s.accountID, Name: displayName, Issued: types.GroupIssuedIntegration}
	s.groups[created.ID] = created
	s.applyMembers(created, memberUserIDs)
	return created, true, nil
}

func (s *stubAccountWriter) applyMembers(group *types.Group, memberUserIDs []string) {
	for _, user := range s.users {
		member := false
		for _, id := range memberUserIDs {
			if user.Id == id {
				member = true
				break
			}
		}
		had := false
		for _, id := range user.AutoGroups {
			if id == group.ID {
				had = true
				break
			}
		}
		if member && !had {
			user.AutoGroups = append(user.AutoGroups, group.ID)
		}
		if !member && had {
			filtered := make([]string, 0, len(user.AutoGroups))
			for _, id := range user.AutoGroups {
				if id != group.ID {
					filtered = append(filtered, id)
				}
			}
			user.AutoGroups = filtered
		}
	}
}

func (s *stubAccountWriter) SCIMUpdateGroup(_ context.Context, _, groupID, displayName string, memberUserIDs []string) (*types.Group, error) {
	group, ok := s.groups[groupID]
	if !ok {
		return nil, status.NewGroupNotFoundError(groupID)
	}
	if group.Issued != types.GroupIssuedIntegration {
		return nil, status.Errorf(status.PermissionDenied, "cannot modify non-integration group via SCIM")
	}
	if displayName != "" {
		group.Name = displayName
	}
	s.applyMembers(group, memberUserIDs)
	return group, nil
}

func (s *stubAccountWriter) SCIMGetGroup(_ context.Context, _, groupID string) (*types.Group, []string, error) {
	group, ok := s.groups[groupID]
	if !ok {
		return nil, nil, status.NewGroupNotFoundError(groupID)
	}
	var memberIDs []string
	for _, user := range s.users {
		for _, id := range user.AutoGroups {
			if id == groupID {
				memberIDs = append(memberIDs, user.Id)
				break
			}
		}
	}
	return group, memberIDs, nil
}

func doRequest(t *testing.T, srv *httptest.Server, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()

	var req *http.Request
	var err error
	if body != "" {
		req, err = http.NewRequest(method, srv.URL+path, bytes.NewBufferString(body))
	} else {
		req, err = http.NewRequest(method, srv.URL+path, nil)
	}
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", contentType)
	}

	recorder := httptest.NewRecorder()
	srv.Config.Handler.ServeHTTP(recorder, req)
	return recorder
}

func (s *stubAccountWriter) SCIMListGroups(_ context.Context, _ string) ([]*types.Group, error) {
	groups := make([]*types.Group, 0, len(s.groups))
	for _, id := range []string{"grp-jwt", "grp-api", "grp-int"} {
		if group, ok := s.groups[id]; ok {
			groups = append(groups, group)
		}
	}
	return groups, nil
}

func (s *stubAccountWriter) SCIMDeleteGroup(_ context.Context, _, groupID string) error {
	group, ok := s.groups[groupID]
	if !ok {
		return status.NewGroupNotFoundError(groupID)
	}
	if group.Issued != types.GroupIssuedIntegration {
		return status.Errorf(status.PermissionDenied, "cannot delete non-integration group via SCIM")
	}
	s.applyMembers(group, nil)
	delete(s.groups, groupID)
	return nil
}

func newTestServer(writer *stubAccountWriter, enabled bool) *httptest.Server {
	router := mux.NewRouter()
	cfg := &config.SCIMConfig{Enabled: enabled, Token: testToken}
	AddEndpoints(writer, router, cfg)
	return httptest.NewServer(router)
}

func TestServiceProviderConfig(t *testing.T) {
	srv := newTestServer(newStubWriter(), true)
	defer srv.Close()

	recorder := doRequest(t, srv, http.MethodGet, "/scim/v2/ServiceProviderConfig", testToken, "")
	require.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, contentType, recorder.Header().Get("Content-Type"))

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &parsed))

	schemas, ok := parsed["schemas"].([]any)
	require.True(t, ok, "schemas must be an array")
	assert.Equal(t, schemaServiceProviderConfig, schemas[0])

	patch, ok := parsed["patch"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, false, patch["supported"])

	bulk, ok := parsed["bulk"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, false, bulk["supported"])
	assert.Equal(t, float64(0), bulk["maxOperations"])

	schemes, ok := parsed["authenticationSchemes"].([]any)
	require.True(t, ok)
	scheme, ok := schemes[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "oauthbearertoken", scheme["type"])
	assert.Equal(t, true, scheme["primary"])
}

func TestBearerAuth(t *testing.T) {
	srv := newTestServer(newStubWriter(), true)
	defer srv.Close()

	path := "/scim/v2/ServiceProviderConfig"

	recorder := doRequest(t, srv, http.MethodGet, path, testToken, "")
	assert.Equal(t, http.StatusOK, recorder.Code)

	recorder = doRequest(t, srv, http.MethodGet, path, "wrong-token", "")
	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	assert.Equal(t, "Bearer", recorder.Header().Get("WWW-Authenticate"))
	assertSCIMErrorEnvelope(t, recorder)

	recorder = doRequest(t, srv, http.MethodGet, path, "", "")
	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
}

func TestDisabledConfigRegistersNothing(t *testing.T) {
	srv := newTestServer(newStubWriter(), false)
	defer srv.Close()

	recorder := doRequest(t, srv, http.MethodGet, "/scim/v2/ServiceProviderConfig", testToken, "")
	assert.Equal(t, http.StatusNotFound, recorder.Code)
}

func assertSCIMErrorEnvelope(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	var body map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	schemas, ok := body["schemas"].([]any)
	require.True(t, ok)
	assert.Equal(t, schemaError, schemas[0])
	assert.Equal(t, float64(recorder.Code), body["status"])
	assert.NotEmpty(t, body["detail"])
	assert.Equal(t, contentType, recorder.Header().Get("Content-Type"))
}

func TestListUsersPagination(t *testing.T) {
	srv := newTestServer(newStubWriter(), true)
	defer srv.Close()

	recorder := doRequest(t, srv, http.MethodGet, "/scim/v2/Users?startIndex=2&count=2", testToken, "")
	require.Equal(t, http.StatusOK, recorder.Code)

	var page scimListResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &page))
	assert.Equal(t, 5, page.TotalResults)
	assert.Equal(t, 2, page.StartIndex)
	assert.Equal(t, 2, page.ItemsPerPage)
	require.Len(t, page.Resources, 2)
	first := page.Resources[0].(map[string]any)
	assert.Equal(t, "user-b", first["id"])

	recorder = doRequest(t, srv, http.MethodGet, "/scim/v2/Users?startIndex=10", testToken, "")
	require.Equal(t, http.StatusOK, recorder.Code)
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &page))
	assert.Equal(t, 5, page.TotalResults)
	assert.Equal(t, 0, page.ItemsPerPage)
	require.NotNil(t, page.Resources)
	assert.Empty(t, page.Resources)
}

func TestPageParams(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "/?startIndex=abc&count=-3", nil)
	require.NoError(t, err)
	startIndex, count := pageParams(req)
	assert.Equal(t, 1, startIndex)
	assert.Equal(t, defaultPageCount, count)

	req, _ = http.NewRequest(http.MethodGet, "/?startIndex=0&count=9999", nil)
	startIndex, count = pageParams(req)
	assert.Equal(t, 1, startIndex)
	assert.Equal(t, maxPageCount, count)
}

func TestUpsertUser(t *testing.T) {
	writer := newStubWriter()
	srv := newTestServer(writer, true)
	defer srv.Close()

	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"dev1","externalId":"dev1-ext-id","displayName":"Dev One","emails":[{"value":"dev1@example.com","primary":true}],"active":true}`
	recorder := doRequest(t, srv, http.MethodPost, "/scim/v2/Users", testToken, body)
	require.Equal(t, http.StatusCreated, recorder.Code)

	var created map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &created))
	assert.Equal(t, "dev1-ext-id", created["id"])
	assert.Equal(t, "dev1-ext-id", created["externalId"])
	assert.Equal(t, true, created["active"])

	recorder = doRequest(t, srv, http.MethodPost, "/scim/v2/Users", testToken, body)
	require.Equal(t, http.StatusOK, recorder.Code)

	recorder = doRequest(t, srv, http.MethodPut, "/scim/v2/Users/dev1-ext-id", testToken, `{"userName":"dev1","active":false}`)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &created))
	assert.Equal(t, false, created["active"])

	recorder = doRequest(t, srv, http.MethodDelete, "/scim/v2/Users/dev1-ext-id", testToken, "")
	require.Equal(t, http.StatusNoContent, recorder.Code)
	assert.True(t, writer.users["dev1-ext-id"].Blocked)

	recorder = doRequest(t, srv, http.MethodDelete, "/scim/v2/Users/no-such-user", testToken, "")
	assert.Equal(t, http.StatusNotFound, recorder.Code)
	assertSCIMErrorEnvelope(t, recorder)
}

func TestUnknownFieldRejected(t *testing.T) {
	srv := newTestServer(newStubWriter(), true)
	defer srv.Close()

	recorder := doRequest(t, srv, http.MethodPost, "/scim/v2/Users", testToken, `{"userName":"x","totallyUnknown":1}`)
	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assertSCIMErrorEnvelope(t, recorder)
}

func TestUpsertGroup(t *testing.T) {
	writer := newStubWriter()
	srv := newTestServer(writer, true)
	defer srv.Close()

	body := func(name, member string) string {
		return fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":%q,"members":[{"value":%q}]}`, name, member)
	}

	recorder := doRequest(t, srv, http.MethodPost, "/scim/v2/Groups", testToken, body("brand-new", "user-a"))
	require.Equal(t, http.StatusCreated, recorder.Code)
	var group map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &group))
	assert.Equal(t, "grp-new-brand-new", group["id"])

	recorder = doRequest(t, srv, http.MethodPost, "/scim/v2/Groups", testToken, body("from-jwt", "user-a"))
	require.Equal(t, http.StatusOK, recorder.Code)
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &group))
	assert.Equal(t, "grp-jwt", group["id"])
	assert.Equal(t, types.GroupIssuedIntegration, writer.groups["grp-jwt"].Issued)

	recorder = doRequest(t, srv, http.MethodPost, "/scim/v2/Groups", testToken, body("from-api", "user-a"))
	assert.Equal(t, http.StatusConflict, recorder.Code)
	assertSCIMErrorEnvelope(t, recorder)
}

func TestGroupMembersAlwaysPresent(t *testing.T) {
	writer := newStubWriter()
	srv := newTestServer(writer, true)
	defer srv.Close()

	recorder := doRequest(t, srv, http.MethodGet, "/scim/v2/Groups/grp-int", testToken, "")
	require.Equal(t, http.StatusOK, recorder.Code)

	var group scimGroup
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &group))
	require.NotNil(t, group.Members, "members must always be present, even empty")
	assert.Empty(t, group.Members)
}

func TestPatchRejected(t *testing.T) {
	srv := newTestServer(newStubWriter(), true)
	defer srv.Close()

	for _, path := range []string{"/scim/v2/Users/user-a", "/scim/v2/Groups/grp-int", "/scim/v2/Users"} {
		recorder := doRequest(t, srv, http.MethodPatch, path, testToken, `{"Operations":[]}`)
		assert.Equal(t, http.StatusBadRequest, recorder.Code, path)
		var body map[string]any
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
		assert.Contains(t, body["detail"], "PATCH is not supported")
	}
}

func TestUnknownRouteNotFound(t *testing.T) {
	srv := newTestServer(newStubWriter(), true)
	defer srv.Close()

	recorder := doRequest(t, srv, http.MethodGet, "/scim/v2/Bulk", testToken, "")
	assert.Equal(t, http.StatusNotFound, recorder.Code)

	recorder = doRequest(t, srv, http.MethodPost, "/scim/v2/Groups/grp-int", testToken, "{}")
	assert.Equal(t, http.StatusBadRequest, recorder.Code)
}
