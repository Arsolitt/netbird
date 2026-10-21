//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools"
	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools/channel"
	"github.com/netbirdio/netbird/management/server/types"
)

const scimToken = "test-scim-token"

func scimRequest(t *testing.T, body string, method, path, token string) *http.Request {
	t.Helper()
	req := testing_tools.BuildRequest(t, []byte(body), method, path, token)
	req.Header.Set("Content-Type", "application/scim+json")
	return req
}

func scimSetup(t *testing.T) (http.Handler, account.Manager, chan struct{}) {
	t.Helper()

	channel.SCIMTestConfig = &config.SCIMConfig{Enabled: true, Token: scimToken}
	t.Cleanup(func() { channel.SCIMTestConfig = nil })

	apiHandler, am, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/groups.sql", nil, true)
	return apiHandler, am, done
}

func waitDone(t *testing.T, done chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("timeout waiting for peerShouldNotReceiveUpdate")
	}
}

func Test_Scim_ServiceProviderConfig(t *testing.T) {
	apiHandler, _, done := scimSetup(t)

	recorder := httptest.NewRecorder()
	apiHandler.ServeHTTP(recorder, scimRequest(t, "", http.MethodGet, "/api/scim/v2/ServiceProviderConfig", scimToken))
	require.Equal(t, http.StatusOK, recorder.Code)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &parsed))
	patch := parsed["patch"].(map[string]any)
	assert.Equal(t, false, patch["supported"])

	recorder = httptest.NewRecorder()
	apiHandler.ServeHTTP(recorder, scimRequest(t, "", http.MethodGet, "/api/scim/v2/ServiceProviderConfig", "wrong-token"))
	assert.Equal(t, http.StatusUnauthorized, recorder.Code)

	waitDone(t, done)
}

func Test_Scim_UserLifecycle(t *testing.T) {
	apiHandler, am, done := scimSetup(t)
	ctx := context.Background()

	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"dev1","externalId":"dev1-ext-id","displayName":"Dev One","emails":[{"value":"dev1@example.com","primary":true}],"active":true}`
	recorder := httptest.NewRecorder()
	apiHandler.ServeHTTP(recorder, scimRequest(t, body, http.MethodPost, "/api/scim/v2/Users", scimToken))
	require.Equal(t, http.StatusCreated, recorder.Code)

	var created map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &created))
	assert.Equal(t, "dev1-ext-id", created["id"])

	user, err := am.GetUserByID(ctx, "dev1-ext-id")
	require.NoError(t, err)
	assert.Equal(t, types.UserIssuedIntegration, user.Issued)
	assert.Equal(t, testing_tools.TestAccountId, user.AccountID)
	assert.False(t, user.Blocked)

	recorder = httptest.NewRecorder()
	apiHandler.ServeHTTP(recorder, scimRequest(t, `{"userName":"dev1","active":false}`, http.MethodPut, "/api/scim/v2/Users/dev1-ext-id", scimToken))
	require.Equal(t, http.StatusOK, recorder.Code)

	user, err = am.GetUserByID(ctx, "dev1-ext-id")
	require.NoError(t, err)
	assert.True(t, user.Blocked)

	waitDone(t, done)
}

func Test_Scim_GroupAdoption(t *testing.T) {
	apiHandler, am, done := scimSetup(t)
	ctx := context.Background()

	require.NoError(t, am.CreateGroup(ctx, testing_tools.TestAccountId, activity.SystemInitiator, &types.Group{Name: "adopt-me", Issued: types.GroupIssuedJWT}))
	preExisting, err := am.GetGroupByName(ctx, "adopt-me", testing_tools.TestAccountId, activity.SystemInitiator)
	require.NoError(t, err)

	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"adopt-me","members":[{"value":"` + testing_tools.TestUserId + `"}]}`
	recorder := httptest.NewRecorder()
	apiHandler.ServeHTTP(recorder, scimRequest(t, body, http.MethodPost, "/api/scim/v2/Groups", scimToken))
	require.Equal(t, http.StatusOK, recorder.Code)

	var group map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &group))
	assert.Equal(t, preExisting.ID, group["id"], "adoption must keep the group ID")

	adopted, err := am.GetGroupByName(ctx, "adopt-me", testing_tools.TestAccountId, activity.SystemInitiator)
	require.NoError(t, err)
	assert.Equal(t, types.GroupIssuedIntegration, adopted.Issued)

	user, err := am.GetUserByID(ctx, testing_tools.TestUserId)
	require.NoError(t, err)
	assert.Contains(t, user.AutoGroups, preExisting.ID)

	waitDone(t, done)
}

func Test_Scim_GroupLifecycle(t *testing.T) {
	apiHandler, am, done := scimSetup(t)
	ctx := context.Background()

	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"scim-fresh","members":[{"value":"` + testing_tools.TestUserId + `"}]}`
	recorder := httptest.NewRecorder()
	apiHandler.ServeHTTP(recorder, scimRequest(t, body, http.MethodPost, "/api/scim/v2/Groups", scimToken))
	require.Equal(t, http.StatusCreated, recorder.Code)

	var created map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &created))
	groupID := created["id"].(string)
	assert.NotEmpty(t, groupID)

	user, err := am.GetUserByID(ctx, testing_tools.TestUserId)
	require.NoError(t, err)
	assert.Contains(t, user.AutoGroups, groupID)

	admin := testing_tools.TestAdminId
	update := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"scim-fresh","members":[{"value":"` + admin + `"}]}`
	recorder = httptest.NewRecorder()
	apiHandler.ServeHTTP(recorder, scimRequest(t, update, http.MethodPut, "/api/scim/v2/Groups/"+groupID, scimToken))
	require.Equal(t, http.StatusOK, recorder.Code)

	user, err = am.GetUserByID(ctx, testing_tools.TestUserId)
	require.NoError(t, err)
	assert.NotContains(t, user.AutoGroups, groupID)
	adminUser, err := am.GetUserByID(ctx, admin)
	require.NoError(t, err)
	assert.Contains(t, adminUser.AutoGroups, groupID)

	recorder = httptest.NewRecorder()
	apiHandler.ServeHTTP(recorder, scimRequest(t, "", http.MethodGet, "/api/scim/v2/Groups/"+groupID, scimToken))
	require.Equal(t, http.StatusOK, recorder.Code)
	var fetched struct {
		Members []struct {
			Value string `json:"value"`
		} `json:"members"`
	}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &fetched))
	require.Len(t, fetched.Members, 1)
	assert.Equal(t, admin, fetched.Members[0].Value)

	recorder = httptest.NewRecorder()
	apiHandler.ServeHTTP(recorder, scimRequest(t, "", http.MethodDelete, "/api/scim/v2/Groups/"+groupID, scimToken))
	require.Equal(t, http.StatusNoContent, recorder.Code)

	groups, err := am.GetAllGroups(ctx, testing_tools.TestAccountId, activity.SystemInitiator)
	require.NoError(t, err)
	for _, group := range groups {
		assert.NotEqual(t, groupID, group.ID)
	}
	adminUser, err = am.GetUserByID(ctx, admin)
	require.NoError(t, err)
	assert.NotContains(t, adminUser.AutoGroups, groupID)

	waitDone(t, done)
}

func Test_Scim_ApiGroupConflict(t *testing.T) {
	apiHandler, am, done := scimSetup(t)
	ctx := context.Background()

	require.NoError(t, am.CreateGroup(ctx, testing_tools.TestAccountId, activity.SystemInitiator, &types.Group{Name: "api-owned", Issued: types.GroupIssuedAPI}))

	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"api-owned","members":[]}`
	recorder := httptest.NewRecorder()
	apiHandler.ServeHTTP(recorder, scimRequest(t, body, http.MethodPost, "/api/scim/v2/Groups", scimToken))
	assert.Equal(t, http.StatusConflict, recorder.Code)
	assert.True(t, strings.Contains(recorder.Body.String(), "rename or convert"))

	waitDone(t, done)
}
