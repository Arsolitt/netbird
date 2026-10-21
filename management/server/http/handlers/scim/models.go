package scim

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/netbirdio/netbird/management/server/types"
)

const (
	schemaError                 = "urn:ietf:params:scim:api:messages:2.0:Error"
	schemaListResponse          = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	schemaUser                  = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaGroup                 = "urn:ietf:params:scim:schemas:core:2.0:Group"
	schemaServiceProviderConfig = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"

	contentType = "application/scim+json"
)

type scimError struct {
	Schemas []string `json:"schemas"`
	Status  int      `json:"status"`
	Detail  string   `json:"detail"`
}

type scimFeature struct {
	Supported bool `json:"supported"`
}

type scimBulk struct {
	Supported      bool `json:"supported"`
	MaxOperations  int  `json:"maxOperations"`
	MaxPayloadSize int  `json:"maxPayloadSize"`
}

type scimFilter struct {
	Supported  bool `json:"supported"`
	MaxResults int  `json:"maxResults"`
}

type scimAuthScheme struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Primary     bool   `json:"primary"`
}

type scimServiceProviderConfig struct {
	Schemas               []string         `json:"schemas"`
	Patch                 scimFeature      `json:"patch"`
	Bulk                  scimBulk         `json:"bulk"`
	Filter                scimFilter       `json:"filter"`
	ChangePassword        scimFeature      `json:"changePassword"`
	Sort                  scimFeature      `json:"sort"`
	Etag                  scimFeature      `json:"etag"`
	AuthenticationSchemes []scimAuthScheme `json:"authenticationSchemes"`
}

type scimName struct {
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

type scimEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary"`
}

type scimUser struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id"`
	UserName    string      `json:"userName"`
	ExternalID  string      `json:"externalId"`
	Active      bool        `json:"active"`
	DisplayName string      `json:"displayName,omitempty"`
	Name        *scimName   `json:"name,omitempty"`
	Emails      []scimEmail `json:"emails,omitempty"`
}

type scimMember struct {
	Value   string `json:"value"`
	Display string `json:"display"`
}

type scimGroup struct {
	Schemas     []string     `json:"schemas"`
	ID          string       `json:"id"`
	DisplayName string       `json:"displayName"`
	Members     []scimMember `json:"members"`
}

type scimListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    []any    `json:"Resources"`
}

type scimNameRequest struct {
	GivenName  string `json:"givenName"`
	FamilyName string `json:"familyName"`
}

type scimEmailRequest struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary"`
}

type scimUserRequest struct {
	// Authentik echoes the stored id in PUT bodies; accepted and ignored, the
	// request path is authoritative.
	ID          string             `json:"id"`
	Schemas     []string           `json:"schemas"`
	UserName    string             `json:"userName"`
	ExternalID  string             `json:"externalId"`
	Active      *bool              `json:"active"`
	DisplayName string             `json:"displayName"`
	Name        *scimNameRequest   `json:"name"`
	Emails      []scimEmailRequest `json:"emails"`
}

type scimMemberRequest struct {
	Value string `json:"value"`
}

type scimGroupRequest struct {
	// Authentik sends its group pk as externalId and echoes the stored id in
	// PUT bodies; both accepted and ignored, the request path is authoritative.
	ID          string              `json:"id"`
	ExternalID  string              `json:"externalId"`
	Schemas     []string            `json:"schemas"`
	DisplayName string              `json:"displayName"`
	Members     []scimMemberRequest `json:"members"`
}

func toSCIMUser(user *types.User) scimUser {
	return scimUser{
		Schemas:     []string{schemaUser},
		ID:          user.Id,
		UserName:    user.Id,
		ExternalID:  user.Id,
		Active:      !user.Blocked,
		DisplayName: user.Name,
		Emails:      emailsOf(user),
	}
}

func emailsOf(user *types.User) []scimEmail {
	if user.Email == "" {
		return nil
	}
	return []scimEmail{{Value: user.Email, Primary: true}}
}

func toSCIMGroup(group *types.Group, memberUsers []*types.User) scimGroup {
	members := make([]scimMember, 0, len(memberUsers))
	for _, user := range memberUsers {
		display := user.Name
		if display == "" {
			display = user.Id
		}
		members = append(members, scimMember{Value: user.Id, Display: display})
	}
	return scimGroup{
		Schemas:     []string{schemaGroup},
		ID:          group.ID,
		DisplayName: group.Name,
		Members:     members,
	}
}

func (r scimGroupRequest) memberUserIDs() []string {
	ids := make([]string, 0, len(r.Members))
	for _, member := range r.Members {
		if member.Value != "" {
			ids = append(ids, member.Value)
		}
	}
	return ids
}

func serviceProviderConfig() scimServiceProviderConfig {
	return scimServiceProviderConfig{
		Schemas:        []string{schemaServiceProviderConfig},
		Patch:          scimFeature{Supported: false},
		Bulk:           scimBulk{Supported: false},
		Filter:         scimFilter{Supported: false},
		ChangePassword: scimFeature{Supported: false},
		Sort:           scimFeature{Supported: false},
		Etag:           scimFeature{Supported: false},
		AuthenticationSchemes: []scimAuthScheme{{
			Type:        "oauthbearertoken",
			Name:        "Bearer Token",
			Description: "Static bearer token",
			Primary:     true,
		}},
	}
}

// writeSCIMJSON writes a SCIM response body with the required content type.
func writeSCIMJSON(w http.ResponseWriter, statusCode int, body any) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(body)
}

func writeSCIMError(w http.ResponseWriter, statusCode int, detail string) {
	writeSCIMJSON(w, statusCode, scimError{
		Schemas: []string{schemaError},
		Status:  statusCode,
		Detail:  detail,
	})
}

// decodeSCIMRequest decodes a SCIM request body, rejecting unknown fields so
// client drift surfaces instead of silently dropping data.
func decodeSCIMRequest(r *http.Request, into any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return fmt.Errorf("invalid request body: %w", err)
	}
	return nil
}
