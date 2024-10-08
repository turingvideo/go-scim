package service

import (
	"context"
	"encoding/json"
	"github.com/imulab/go-scim/pkg/v2/crud"
	"github.com/imulab/go-scim/pkg/v2/db"
	"github.com/imulab/go-scim/pkg/v2/prop"
	"github.com/imulab/go-scim/pkg/v2/service/filter"
	"github.com/imulab/go-scim/pkg/v2/spec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

func TestPatchService(t *testing.T) {
	s := new(PatchServiceTestSuite)
	suite.Run(t, s)
}

type PatchServiceTestSuite struct {
	suite.Suite
	resourceType *spec.ResourceType
	config       *spec.ServiceProviderConfig
}

func (s *PatchServiceTestSuite) TestDo() {
	tests := []struct {
		name       string
		setup      func(t *testing.T) Patch
		getRequest func() *PatchRequest
		expect     func(t *testing.T, resp *PatchResponse, err error)
	}{
		{
			name: "patch to make a difference",
			setup: func(t *testing.T) Patch {
				database := db.Memory()
				err := database.Insert(context.TODO(), s.resourceOf(t, map[string]interface{}{
					"schemas":  []interface{}{"urn:ietf:params:scim:schemas:core:2.0:User"},
					"id":       "foo",
					"userName": "foo",
					"timezone": "Asia/Shanghai",
					"emails": []interface{}{
						map[string]interface{}{
							"value": "foo@bar.com",
							"type":  "home",
						},
					},
				}))
				require.Nil(t, err)
				return PatchService(s.config, database, nil, []filter.ByResource{
					filter.ByPropertyToByResource(
						filter.ReadOnlyFilter(),
						filter.BCryptFilter(),
					),
					filter.ByPropertyToByResource(filter.ValidationFilter(database)),
					filter.MetaFilter(),
				})
			},
			getRequest: func() *PatchRequest {
				return &PatchRequest{
					ResourceID: "foo",
					PayloadSource: strings.NewReader(`
		{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			"Operations": [
				{
					"op": "add",
					"path": "userName",
					"value": "foobar"
				},
				{
					"op": "replace",
					"path": "emails[value eq \"foo@bar.com\"].type",
					"value": "work"
				},
				{
					"op": "remove",
					"path": "timezone"
				}
			]
		}
		`),
				}
			},
			expect: func(t *testing.T, resp *PatchResponse, err error) {
				assert.Nil(t, err)
				assert.True(t, resp.Patched)
				assert.NotEmpty(t, resp.Resource.MetaVersionOrEmpty())
				assert.NotEqual(t, resp.Ref.MetaVersionOrEmpty(), resp.Resource.MetaVersionOrEmpty())
				assert.Equal(t, "foobar", resp.Resource.Navigator().Dot("userName").Current().Raw())
				assert.True(t, resp.Resource.Navigator().Dot("timezone").Current().IsUnassigned())
				assert.Equal(t, "work", resp.Resource.Navigator().Dot("emails").At(0).Dot("type").Current().Raw())
			},
		},
		{
			name: "patch to not make a difference",
			setup: func(t *testing.T) Patch {
				database := db.Memory()
				err := database.Insert(context.TODO(), s.resourceOf(t, map[string]interface{}{
					"schemas":  []interface{}{"urn:ietf:params:scim:schemas:core:2.0:User"},
					"id":       "foo",
					"userName": "foo",
					"timezone": "Asia/Shanghai",
					"emails": []interface{}{
						map[string]interface{}{
							"value": "foo@bar.com",
							"type":  "home",
						},
					},
				}))
				require.Nil(t, err)
				return PatchService(s.config, database, nil, []filter.ByResource{
					filter.ByPropertyToByResource(
						filter.ReadOnlyFilter(),
						filter.BCryptFilter(),
					),
					filter.ByPropertyToByResource(filter.ValidationFilter(database)),
					filter.MetaFilter(),
				})
			},
			getRequest: func() *PatchRequest {
				return &PatchRequest{
					ResourceID: "foo",
					PayloadSource: strings.NewReader(`
		{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			"Operations": [
				{
					"op": "add",
					"path": "userName",
					"value": "foo"
				}
			]
		}
		`),
				}
			},
			expect: func(t *testing.T, resp *PatchResponse, err error) {
				assert.Nil(t, err)
				assert.False(t, resp.Patched)
			},
		},
		{
			name: "patch to make a difference with upper case OP",
			setup: func(t *testing.T) Patch {
				database := db.Memory()
				err := database.Insert(context.TODO(), s.resourceOf(t, map[string]interface{}{
					"schemas":  []interface{}{"urn:ietf:params:scim:schemas:core:2.0:User"},
					"id":       "foo",
					"userName": "foo",
					"timezone": "Asia/Shanghai",
					"emails": []interface{}{
						map[string]interface{}{
							"value": "foo@bar.com",
							"type":  "home",
						},
					},
				}))
				require.Nil(t, err)
				return PatchService(s.config, database, nil, []filter.ByResource{
					filter.ByPropertyToByResource(
						filter.ReadOnlyFilter(),
						filter.BCryptFilter(),
					),
					filter.ByPropertyToByResource(filter.ValidationFilter(database)),
					filter.MetaFilter(),
				})
			},
			getRequest: func() *PatchRequest {
				return &PatchRequest{
					ResourceID: "foo",
					PayloadSource: strings.NewReader(`
		{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			"Operations": [
				{
					"op": "ADD",
					"path": "userName",
					"value": "foobar"
				},
				{
					"op": "REPLACE",
					"path": "emails[value eq \"foo@bar.com\"].type",
					"value": "work"
				},
				{
					"op": "REMOVE",
					"path": "timezone"
				}
			]
		}
		`),
				}
			},
			expect: func(t *testing.T, resp *PatchResponse, err error) {
				assert.Nil(t, err)
				assert.True(t, resp.Patched)
				assert.NotEmpty(t, resp.Resource.MetaVersionOrEmpty())
				assert.NotEqual(t, resp.Ref.MetaVersionOrEmpty(), resp.Resource.MetaVersionOrEmpty())
				assert.Equal(t, "foobar", resp.Resource.Navigator().Dot("userName").Current().Raw())
				assert.True(t, resp.Resource.Navigator().Dot("timezone").Current().IsUnassigned())
				assert.Equal(t, "work", resp.Resource.Navigator().Dot("emails").At(0).Dot("type").Current().Raw())
			},
		},
		{
			name: "patch to make a difference from root of the resource",
			setup: func(t *testing.T) Patch {
				database := db.Memory()
				err := database.Insert(context.TODO(), s.resourceOf(t, map[string]interface{}{
					"schemas":  []interface{}{"urn:ietf:params:scim:schemas:core:2.0:User"},
					"id":       "foo",
					"userName": "foo",
					"timezone": "Asia/Shanghai",
					"emails": []interface{}{
						map[string]interface{}{
							"value": "foo@bar.com",
							"type":  "home",
						},
					},
				}))
				require.Nil(t, err)
				return PatchService(s.config, database, nil, []filter.ByResource{
					filter.ByPropertyToByResource(
						filter.ReadOnlyFilter(),
						filter.BCryptFilter(),
					),
					filter.ByPropertyToByResource(filter.ValidationFilter(database)),
					filter.MetaFilter(),
				})
			},
			getRequest: func() *PatchRequest {
				return &PatchRequest{
					ResourceID: "foo",
					PayloadSource: strings.NewReader(`
{
	"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
	"Operations": [
		{
			"op": "replace",
			"value": {
				"userName": "bar",
				"password": "a-new-password"
			}
		}
	]
}
`),
				}
			},
			expect: func(t *testing.T, resp *PatchResponse, err error) {
				assert.Nil(t, err)
				assert.True(t, resp.Patched)
				assert.Equal(t, "bar", resp.Resource.Navigator().Dot("userName").Current().Raw())
				assert.Nil(t, bcrypt.CompareHashAndPassword(
					[]byte(resp.Resource.Navigator().Dot("password").Current().Raw().(string)),
					[]byte("a-new-password"),
				))
			},
		},
		{
			name: "patch a field in the schema extension",
			setup: func(t *testing.T) Patch {
				database := db.Memory()
				err := database.Insert(context.TODO(), s.resourceOf(t, map[string]interface{}{
					"schemas": []interface{}{
						"urn:ietf:params:scim:schemas:core:2.0:User",
						"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
					},
					"id":       "foo",
					"userName": "foo",
					"emails": []interface{}{
						map[string]interface{}{
							"value": "foo@bar.com",
							"type":  "home",
						},
					},
					"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": map[string]interface{}{
						"employeeNumber": "1234567",
					},
				}))
				require.Nil(t, err)
				return PatchService(s.config, database, nil, []filter.ByResource{
					filter.ByPropertyToByResource(
						filter.ReadOnlyFilter(),
						filter.BCryptFilter(),
					),
					filter.ByPropertyToByResource(filter.ValidationFilter(database)),
					filter.MetaFilter(),
				})
			},
			getRequest: func() *PatchRequest {
				return &PatchRequest{
					ResourceID: "foo",
					PayloadSource: strings.NewReader(`
		{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			"Operations": [
				{
					"op": "add",
					"path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber",
					"value": "6546579"
				}
			]
		}
		`),
				}
			},
			expect: func(t *testing.T, resp *PatchResponse, err error) {
				assert.Nil(t, err)
				assert.True(t, resp.Patched)
				assert.Equal(t, "6546579", resp.Resource.Navigator().Dot("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User").Dot("employeeNumber").Current().Raw())
			},
		},
	}

	for _, test := range tests {
		s.T().Run(test.name, func(t *testing.T) {
			service := test.setup(t)
			resp, err := service.Do(context.TODO(), test.getRequest())
			test.expect(t, resp, err)
		})
	}
}

func (s *PatchServiceTestSuite) resourceOf(t *testing.T, data interface{}) *prop.Resource {
	r := prop.NewResource(s.resourceType)
	require.Nil(t, r.Navigator().Replace(data).Error())
	return r
}

func (s *PatchServiceTestSuite) SetupSuite() {
	for _, each := range []struct {
		filepath  string
		structure interface{}
		post      func(parsed interface{})
	}{
		{
			filepath:  "../../../public/schemas/core_schema.json",
			structure: new(spec.Schema),
			post: func(parsed interface{}) {
				spec.Schemas().Register(parsed.(*spec.Schema))
			},
		},
		{
			filepath:  "../../../public/schemas/user_schema.json",
			structure: new(spec.Schema),
			post: func(parsed interface{}) {
				spec.Schemas().Register(parsed.(*spec.Schema))
			},
		},
		{
			filepath:  "../../../public/schemas/user_enterprise_extension_schema.json",
			structure: new(spec.Schema),
			post: func(parsed interface{}) {
				spec.Schemas().Register(parsed.(*spec.Schema))
			},
		},
		{
			filepath:  "../../../public/resource_types/user_resource_type.json",
			structure: new(spec.ResourceType),
			post: func(parsed interface{}) {
				s.resourceType = parsed.(*spec.ResourceType)
				crud.Register(s.resourceType)
			},
		},
	} {
		f, err := os.Open(each.filepath)
		require.Nil(s.T(), err)

		raw, err := ioutil.ReadAll(f)
		require.Nil(s.T(), err)

		err = json.Unmarshal(raw, each.structure)
		require.Nil(s.T(), err)

		if each.post != nil {
			each.post(each.structure)
		}
	}

	s.config = new(spec.ServiceProviderConfig)
	require.Nil(s.T(), json.Unmarshal([]byte(`
{
  "patch": {
    "supported": true
  }
}
`), s.config))
}

func Test_dealMultiValueSubAttr(t *testing.T) {
	t.Run("not exist", func(t *testing.T) {
		raw := json.RawMessage(`{"emails":[{"value":"aa@com"}],"name":{"givenName":"aa"},"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"School"}}`)
		res, err := dealMultiValueSubAttr(raw, map[string]string{"name": ".", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": ":"})
		assert.Nil(t, err)
		assert.Equal(t, string(raw), string(res))
	})
	t.Run("exist name sub attribute", func(t *testing.T) {
		raw := json.RawMessage(`{"displayName":"Bjfe","name.familyName":"Unua","name.givenName":"Kkom"}`)
		res, err := dealMultiValueSubAttr(raw, map[string]string{"name": ".", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": ":"})
		assert.Nil(t, err)
		expected := json.RawMessage(`{"displayName":"Bjfe","name":{"familyName":"Unua","givenName":"Kkom"}}`)
		assert.Equal(t, string(expected), string(res))
	})
	t.Run("exist enterprise user sub attribute", func(t *testing.T) {
		//"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department": "South View High School"
		raw := json.RawMessage(`{"active":false,"title":"Guidance Counselor","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department":"South View High School"}`)
		res, err := dealMultiValueSubAttr(raw, map[string]string{"name": ".", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": ":"})
		assert.Nil(t, err)
		expected := json.RawMessage(`{"active":false,"title":"Guidance Counselor","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"South View High School"}}`)
		assert.Equal(t, string(expected), string(res))
	})
}
