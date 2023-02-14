/*
Atricore Console :: Remote : API

# Atricore Console API

API version: 1.5.0-SNAPSHOT
Contact: sgonzalez@atricore.com
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package jossoappi

import (
	"encoding/json"
)

// DbIdentitySourceDTO struct for DbIdentitySourceDTO
type DbIdentitySourceDTO struct {
	AcquireIncrement *int32 `json:"acquireIncrement,omitempty"`
	Admin *string `json:"admin,omitempty"`
	ConnectionUrl *string `json:"connectionUrl,omitempty"`
	CredentialsQueryString *string `json:"credentialsQueryString,omitempty"`
	CustomClass *CustomClassDTO `json:"customClass,omitempty"`
	Description *string `json:"description,omitempty"`
	Driver *ResourceDTO `json:"driver,omitempty"`
	DriverName *string `json:"driverName,omitempty"`
	ElementId *string `json:"elementId,omitempty"`
	Id *int64 `json:"id,omitempty"`
	IdleConnectionTestPeriod *int32 `json:"idleConnectionTestPeriod,omitempty"`
	InitialPoolSize *int32 `json:"initialPoolSize,omitempty"`
	MaxIdleTime *int32 `json:"maxIdleTime,omitempty"`
	MaxPoolSize *int32 `json:"maxPoolSize,omitempty"`
	MinPoolSize *int32 `json:"minPoolSize,omitempty"`
	Name *string `json:"name,omitempty"`
	Password *string `json:"password,omitempty"`
	PooledDatasource *bool `json:"pooledDatasource,omitempty"`
	RelayCredentialQueryString *string `json:"relayCredentialQueryString,omitempty"`
	ResetCredentialDml *string `json:"resetCredentialDml,omitempty"`
	RolesQueryString *string `json:"rolesQueryString,omitempty"`
	UseColumnNamesAsPropertyNames *bool `json:"useColumnNamesAsPropertyNames,omitempty"`
	UserPropertiesQueryString *string `json:"userPropertiesQueryString,omitempty"`
	UserQueryString *string `json:"userQueryString,omitempty"`
	X *float64 `json:"x,omitempty"`
	Y *float64 `json:"y,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _DbIdentitySourceDTO DbIdentitySourceDTO

// NewDbIdentitySourceDTO instantiates a new DbIdentitySourceDTO object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewDbIdentitySourceDTO() *DbIdentitySourceDTO {
	this := DbIdentitySourceDTO{}
	return &this
}

// NewDbIdentitySourceDTOWithDefaults instantiates a new DbIdentitySourceDTO object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewDbIdentitySourceDTOWithDefaults() *DbIdentitySourceDTO {
	this := DbIdentitySourceDTO{}
	return &this
}

// GetAcquireIncrement returns the AcquireIncrement field value if set, zero value otherwise.
func (o *DbIdentitySourceDTO) GetAcquireIncrement() int32 {
	if o == nil || isNil(o.AcquireIncrement) {
		var ret int32
		return ret
	}
	return *o.AcquireIncrement
}

// GetAcquireIncrementOk returns a tuple with the AcquireIncrement field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DbIdentitySourceDTO) GetAcquireIncrementOk() (*int32, bool) {
	if o == nil || isNil(o.AcquireIncrement) {
    return nil, false
	}
	return o.AcquireIncrement, true
}

// HasAcquireIncrement returns a boolean if a field has been set.
func (o *DbIdentitySourceDTO) HasAcquireIncrement() bool {
	if o != nil && !isNil(o.AcquireIncrement) {
		return true
	}

	return false
}

// SetAcquireIncrement gets a reference to the given int32 and assigns it to the AcquireIncrement field.
func (o *DbIdentitySourceDTO) SetAcquireIncrement(v int32) {
	o.AcquireIncrement = &v
}

// GetAdmin returns the Admin field value if set, zero value otherwise.
func (o *DbIdentitySourceDTO) GetAdmin() string {
	if o == nil || isNil(o.Admin) {
		var ret string
		return ret
	}
	return *o.Admin
}

// GetAdminOk returns a tuple with the Admin field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DbIdentitySourceDTO) GetAdminOk() (*string, bool) {
	if o == nil || isNil(o.Admin) {
    return nil, false
	}
	return o.Admin, true
}

// HasAdmin returns a boolean if a field has been set.
func (o *DbIdentitySourceDTO) HasAdmin() bool {
	if o != nil && !isNil(o.Admin) {
		return true
	}

	return false
}

// SetAdmin gets a reference to the given string and assigns it to the Admin field.
func (o *DbIdentitySourceDTO) SetAdmin(v string) {
	o.Admin = &v
}

// GetConnectionUrl returns the ConnectionUrl field value if set, zero value otherwise.
func (o *DbIdentitySourceDTO) GetConnectionUrl() string {
	if o == nil || isNil(o.ConnectionUrl) {
		var ret string
		return ret
	}
	return *o.ConnectionUrl
}

// GetConnectionUrlOk returns a tuple with the ConnectionUrl field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DbIdentitySourceDTO) GetConnectionUrlOk() (*string, bool) {
	if o == nil || isNil(o.ConnectionUrl) {
    return nil, false
	}
	return o.ConnectionUrl, true
}

// HasConnectionUrl returns a boolean if a field has been set.
func (o *DbIdentitySourceDTO) HasConnectionUrl() bool {
	if o != nil && !isNil(o.ConnectionUrl) {
		return true
	}

	return false
}

// SetConnectionUrl gets a reference to the given string and assigns it to the ConnectionUrl field.
func (o *DbIdentitySourceDTO) SetConnectionUrl(v string) {
	o.ConnectionUrl = &v
}

// GetCredentialsQueryString returns the CredentialsQueryString field value if set, zero value otherwise.
func (o *DbIdentitySourceDTO) GetCredentialsQueryString() string {
	if o == nil || isNil(o.CredentialsQueryString) {
		var ret string
		return ret
	}
	return *o.CredentialsQueryString
}

// GetCredentialsQueryStringOk returns a tuple with the CredentialsQueryString field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DbIdentitySourceDTO) GetCredentialsQueryStringOk() (*string, bool) {
	if o == nil || isNil(o.CredentialsQueryString) {
    return nil, false
	}
	return o.CredentialsQueryString, true
}

// HasCredentialsQueryString returns a boolean if a field has been set.
func (o *DbIdentitySourceDTO) HasCredentialsQueryString() bool {
	if o != nil && !isNil(o.CredentialsQueryString) {
		return true
	}

	return false
}

// SetCredentialsQueryString gets a reference to the given string and assigns it to the CredentialsQueryString field.
func (o *DbIdentitySourceDTO) SetCredentialsQueryString(v string) {
	o.CredentialsQueryString = &v
}

// GetCustomClass returns the CustomClass field value if set, zero value otherwise.
func (o *DbIdentitySourceDTO) GetCustomClass() CustomClassDTO {
	if o == nil || isNil(o.CustomClass) {
		var ret CustomClassDTO
		return ret
	}
	return *o.CustomClass
}

// GetCustomClassOk returns a tuple with the CustomClass field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DbIdentitySourceDTO) GetCustomClassOk() (*CustomClassDTO, bool) {
	if o == nil || isNil(o.CustomClass) {
    return nil, false
	}
	return o.CustomClass, true
}

// HasCustomClass returns a boolean if a field has been set.
func (o *DbIdentitySourceDTO) HasCustomClass() bool {
	if o != nil && !isNil(o.CustomClass) {
		return true
	}

	return false
}

// SetCustomClass gets a reference to the given CustomClassDTO and assigns it to the CustomClass field.
func (o *DbIdentitySourceDTO) SetCustomClass(v CustomClassDTO) {
	o.CustomClass = &v
}

// GetDescription returns the Description field value if set, zero value otherwise.
func (o *DbIdentitySourceDTO) GetDescription() string {
	if o == nil || isNil(o.Description) {
		var ret string
		return ret
	}
	return *o.Description
}

// GetDescriptionOk returns a tuple with the Description field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DbIdentitySourceDTO) GetDescriptionOk() (*string, bool) {
	if o == nil || isNil(o.Description) {
    return nil, false
	}
	return o.Description, true
}

// HasDescription returns a boolean if a field has been set.
func (o *DbIdentitySourceDTO) HasDescription() bool {
	if o != nil && !isNil(o.Description) {
		return true
	}

	return false
}

// SetDescription gets a reference to the given string and assigns it to the Description field.
func (o *DbIdentitySourceDTO) SetDescription(v string) {
	o.Description = &v
}

// GetDriver returns the Driver field value if set, zero value otherwise.
func (o *DbIdentitySourceDTO) GetDriver() ResourceDTO {
	if o == nil || isNil(o.Driver) {
		var ret ResourceDTO
		return ret
	}
	return *o.Driver
}

// GetDriverOk returns a tuple with the Driver field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DbIdentitySourceDTO) GetDriverOk() (*ResourceDTO, bool) {
	if o == nil || isNil(o.Driver) {
    return nil, false
	}
	return o.Driver, true
}

// HasDriver returns a boolean if a field has been set.
func (o *DbIdentitySourceDTO) HasDriver() bool {
	if o != nil && !isNil(o.Driver) {
		return true
	}

	return false
}

// SetDriver gets a reference to the given ResourceDTO and assigns it to the Driver field.
func (o *DbIdentitySourceDTO) SetDriver(v ResourceDTO) {
	o.Driver = &v
}

// GetDriverName returns the DriverName field value if set, zero value otherwise.
func (o *DbIdentitySourceDTO) GetDriverName() string {
	if o == nil || isNil(o.DriverName) {
		var ret string
		return ret
	}
	return *o.DriverName
}

// GetDriverNameOk returns a tuple with the DriverName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DbIdentitySourceDTO) GetDriverNameOk() (*string, bool) {
	if o == nil || isNil(o.DriverName) {
    return nil, false
	}
	return o.DriverName, true
}

// HasDriverName returns a boolean if a field has been set.
func (o *DbIdentitySourceDTO) HasDriverName() bool {
	if o != nil && !isNil(o.DriverName) {
		return true
	}

	return false
}

// SetDriverName gets a reference to the given string and assigns it to the DriverName field.
func (o *DbIdentitySourceDTO) SetDriverName(v string) {
	o.DriverName = &v
}

// GetElementId returns the ElementId field value if set, zero value otherwise.
func (o *DbIdentitySourceDTO) GetElementId() string {
	if o == nil || isNil(o.ElementId) {
		var ret string
		return ret
	}
	return *o.ElementId
}

// GetElementIdOk returns a tuple with the ElementId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DbIdentitySourceDTO) GetElementIdOk() (*string, bool) {
	if o == nil || isNil(o.ElementId) {
    return nil, false
	}
	return o.ElementId, true
}

// HasElementId returns a boolean if a field has been set.
func (o *DbIdentitySourceDTO) HasElementId() bool {
	if o != nil && !isNil(o.ElementId) {
		return true
	}

	return false
}

// SetElementId gets a reference to the given string and assigns it to the ElementId field.
func (o *DbIdentitySourceDTO) SetElementId(v string) {
	o.ElementId = &v
}

// GetId returns the Id field value if set, zero value otherwise.
func (o *DbIdentitySourceDTO) GetId() int64 {
	if o == nil || isNil(o.Id) {
		var ret int64
		return ret
	}
	return *o.Id
}

// GetIdOk returns a tuple with the Id field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DbIdentitySourceDTO) GetIdOk() (*int64, bool) {
	if o == nil || isNil(o.Id) {
    return nil, false
	}
	return o.Id, true
}

// HasId returns a boolean if a field has been set.
func (o *DbIdentitySourceDTO) HasId() bool {
	if o != nil && !isNil(o.Id) {
		return true
	}

	return false
}

// SetId gets a reference to the given int64 and assigns it to the Id field.
func (o *DbIdentitySourceDTO) SetId(v int64) {
	o.Id = &v
}

// GetIdleConnectionTestPeriod returns the IdleConnectionTestPeriod field value if set, zero value otherwise.
func (o *DbIdentitySourceDTO) GetIdleConnectionTestPeriod() int32 {
	if o == nil || isNil(o.IdleConnectionTestPeriod) {
		var ret int32
		return ret
	}
	return *o.IdleConnectionTestPeriod
}

// GetIdleConnectionTestPeriodOk returns a tuple with the IdleConnectionTestPeriod field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DbIdentitySourceDTO) GetIdleConnectionTestPeriodOk() (*int32, bool) {
	if o == nil || isNil(o.IdleConnectionTestPeriod) {
    return nil, false
	}
	return o.IdleConnectionTestPeriod, true
}

// HasIdleConnectionTestPeriod returns a boolean if a field has been set.
func (o *DbIdentitySourceDTO) HasIdleConnectionTestPeriod() bool {
	if o != nil && !isNil(o.IdleConnectionTestPeriod) {
		return true
	}

	return false
}

// SetIdleConnectionTestPeriod gets a reference to the given int32 and assigns it to the IdleConnectionTestPeriod field.
func (o *DbIdentitySourceDTO) SetIdleConnectionTestPeriod(v int32) {
	o.IdleConnectionTestPeriod = &v
}

// GetInitialPoolSize returns the InitialPoolSize field value if set, zero value otherwise.
func (o *DbIdentitySourceDTO) GetInitialPoolSize() int32 {
	if o == nil || isNil(o.InitialPoolSize) {
		var ret int32
		return ret
	}
	return *o.InitialPoolSize
}

// GetInitialPoolSizeOk returns a tuple with the InitialPoolSize field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DbIdentitySourceDTO) GetInitialPoolSizeOk() (*int32, bool) {
	if o == nil || isNil(o.InitialPoolSize) {
    return nil, false
	}
	return o.InitialPoolSize, true
}

// HasInitialPoolSize returns a boolean if a field has been set.
func (o *DbIdentitySourceDTO) HasInitialPoolSize() bool {
	if o != nil && !isNil(o.InitialPoolSize) {
		return true
	}

	return false
}

// SetInitialPoolSize gets a reference to the given int32 and assigns it to the InitialPoolSize field.
func (o *DbIdentitySourceDTO) SetInitialPoolSize(v int32) {
	o.InitialPoolSize = &v
}

// GetMaxIdleTime returns the MaxIdleTime field value if set, zero value otherwise.
func (o *DbIdentitySourceDTO) GetMaxIdleTime() int32 {
	if o == nil || isNil(o.MaxIdleTime) {
		var ret int32
		return ret
	}
	return *o.MaxIdleTime
}

// GetMaxIdleTimeOk returns a tuple with the MaxIdleTime field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DbIdentitySourceDTO) GetMaxIdleTimeOk() (*int32, bool) {
	if o == nil || isNil(o.MaxIdleTime) {
    return nil, false
	}
	return o.MaxIdleTime, true
}

// HasMaxIdleTime returns a boolean if a field has been set.
func (o *DbIdentitySourceDTO) HasMaxIdleTime() bool {
	if o != nil && !isNil(o.MaxIdleTime) {
		return true
	}

	return false
}

// SetMaxIdleTime gets a reference to the given int32 and assigns it to the MaxIdleTime field.
func (o *DbIdentitySourceDTO) SetMaxIdleTime(v int32) {
	o.MaxIdleTime = &v
}

// GetMaxPoolSize returns the MaxPoolSize field value if set, zero value otherwise.
func (o *DbIdentitySourceDTO) GetMaxPoolSize() int32 {
	if o == nil || isNil(o.MaxPoolSize) {
		var ret int32
		return ret
	}
	return *o.MaxPoolSize
}

// GetMaxPoolSizeOk returns a tuple with the MaxPoolSize field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DbIdentitySourceDTO) GetMaxPoolSizeOk() (*int32, bool) {
	if o == nil || isNil(o.MaxPoolSize) {
    return nil, false
	}
	return o.MaxPoolSize, true
}

// HasMaxPoolSize returns a boolean if a field has been set.
func (o *DbIdentitySourceDTO) HasMaxPoolSize() bool {
	if o != nil && !isNil(o.MaxPoolSize) {
		return true
	}

	return false
}

// SetMaxPoolSize gets a reference to the given int32 and assigns it to the MaxPoolSize field.
func (o *DbIdentitySourceDTO) SetMaxPoolSize(v int32) {
	o.MaxPoolSize = &v
}

// GetMinPoolSize returns the MinPoolSize field value if set, zero value otherwise.
func (o *DbIdentitySourceDTO) GetMinPoolSize() int32 {
	if o == nil || isNil(o.MinPoolSize) {
		var ret int32
		return ret
	}
	return *o.MinPoolSize
}

// GetMinPoolSizeOk returns a tuple with the MinPoolSize field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DbIdentitySourceDTO) GetMinPoolSizeOk() (*int32, bool) {
	if o == nil || isNil(o.MinPoolSize) {
    return nil, false
	}
	return o.MinPoolSize, true
}

// HasMinPoolSize returns a boolean if a field has been set.
func (o *DbIdentitySourceDTO) HasMinPoolSize() bool {
	if o != nil && !isNil(o.MinPoolSize) {
		return true
	}

	return false
}

// SetMinPoolSize gets a reference to the given int32 and assigns it to the MinPoolSize field.
func (o *DbIdentitySourceDTO) SetMinPoolSize(v int32) {
	o.MinPoolSize = &v
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *DbIdentitySourceDTO) GetName() string {
	if o == nil || isNil(o.Name) {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DbIdentitySourceDTO) GetNameOk() (*string, bool) {
	if o == nil || isNil(o.Name) {
    return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *DbIdentitySourceDTO) HasName() bool {
	if o != nil && !isNil(o.Name) {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *DbIdentitySourceDTO) SetName(v string) {
	o.Name = &v
}

// GetPassword returns the Password field value if set, zero value otherwise.
func (o *DbIdentitySourceDTO) GetPassword() string {
	if o == nil || isNil(o.Password) {
		var ret string
		return ret
	}
	return *o.Password
}

// GetPasswordOk returns a tuple with the Password field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DbIdentitySourceDTO) GetPasswordOk() (*string, bool) {
	if o == nil || isNil(o.Password) {
    return nil, false
	}
	return o.Password, true
}

// HasPassword returns a boolean if a field has been set.
func (o *DbIdentitySourceDTO) HasPassword() bool {
	if o != nil && !isNil(o.Password) {
		return true
	}

	return false
}

// SetPassword gets a reference to the given string and assigns it to the Password field.
func (o *DbIdentitySourceDTO) SetPassword(v string) {
	o.Password = &v
}

// GetPooledDatasource returns the PooledDatasource field value if set, zero value otherwise.
func (o *DbIdentitySourceDTO) GetPooledDatasource() bool {
	if o == nil || isNil(o.PooledDatasource) {
		var ret bool
		return ret
	}
	return *o.PooledDatasource
}

// GetPooledDatasourceOk returns a tuple with the PooledDatasource field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DbIdentitySourceDTO) GetPooledDatasourceOk() (*bool, bool) {
	if o == nil || isNil(o.PooledDatasource) {
    return nil, false
	}
	return o.PooledDatasource, true
}

// HasPooledDatasource returns a boolean if a field has been set.
func (o *DbIdentitySourceDTO) HasPooledDatasource() bool {
	if o != nil && !isNil(o.PooledDatasource) {
		return true
	}

	return false
}

// SetPooledDatasource gets a reference to the given bool and assigns it to the PooledDatasource field.
func (o *DbIdentitySourceDTO) SetPooledDatasource(v bool) {
	o.PooledDatasource = &v
}

// GetRelayCredentialQueryString returns the RelayCredentialQueryString field value if set, zero value otherwise.
func (o *DbIdentitySourceDTO) GetRelayCredentialQueryString() string {
	if o == nil || isNil(o.RelayCredentialQueryString) {
		var ret string
		return ret
	}
	return *o.RelayCredentialQueryString
}

// GetRelayCredentialQueryStringOk returns a tuple with the RelayCredentialQueryString field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DbIdentitySourceDTO) GetRelayCredentialQueryStringOk() (*string, bool) {
	if o == nil || isNil(o.RelayCredentialQueryString) {
    return nil, false
	}
	return o.RelayCredentialQueryString, true
}

// HasRelayCredentialQueryString returns a boolean if a field has been set.
func (o *DbIdentitySourceDTO) HasRelayCredentialQueryString() bool {
	if o != nil && !isNil(o.RelayCredentialQueryString) {
		return true
	}

	return false
}

// SetRelayCredentialQueryString gets a reference to the given string and assigns it to the RelayCredentialQueryString field.
func (o *DbIdentitySourceDTO) SetRelayCredentialQueryString(v string) {
	o.RelayCredentialQueryString = &v
}

// GetResetCredentialDml returns the ResetCredentialDml field value if set, zero value otherwise.
func (o *DbIdentitySourceDTO) GetResetCredentialDml() string {
	if o == nil || isNil(o.ResetCredentialDml) {
		var ret string
		return ret
	}
	return *o.ResetCredentialDml
}

// GetResetCredentialDmlOk returns a tuple with the ResetCredentialDml field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DbIdentitySourceDTO) GetResetCredentialDmlOk() (*string, bool) {
	if o == nil || isNil(o.ResetCredentialDml) {
    return nil, false
	}
	return o.ResetCredentialDml, true
}

// HasResetCredentialDml returns a boolean if a field has been set.
func (o *DbIdentitySourceDTO) HasResetCredentialDml() bool {
	if o != nil && !isNil(o.ResetCredentialDml) {
		return true
	}

	return false
}

// SetResetCredentialDml gets a reference to the given string and assigns it to the ResetCredentialDml field.
func (o *DbIdentitySourceDTO) SetResetCredentialDml(v string) {
	o.ResetCredentialDml = &v
}

// GetRolesQueryString returns the RolesQueryString field value if set, zero value otherwise.
func (o *DbIdentitySourceDTO) GetRolesQueryString() string {
	if o == nil || isNil(o.RolesQueryString) {
		var ret string
		return ret
	}
	return *o.RolesQueryString
}

// GetRolesQueryStringOk returns a tuple with the RolesQueryString field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DbIdentitySourceDTO) GetRolesQueryStringOk() (*string, bool) {
	if o == nil || isNil(o.RolesQueryString) {
    return nil, false
	}
	return o.RolesQueryString, true
}

// HasRolesQueryString returns a boolean if a field has been set.
func (o *DbIdentitySourceDTO) HasRolesQueryString() bool {
	if o != nil && !isNil(o.RolesQueryString) {
		return true
	}

	return false
}

// SetRolesQueryString gets a reference to the given string and assigns it to the RolesQueryString field.
func (o *DbIdentitySourceDTO) SetRolesQueryString(v string) {
	o.RolesQueryString = &v
}

// GetUseColumnNamesAsPropertyNames returns the UseColumnNamesAsPropertyNames field value if set, zero value otherwise.
func (o *DbIdentitySourceDTO) GetUseColumnNamesAsPropertyNames() bool {
	if o == nil || isNil(o.UseColumnNamesAsPropertyNames) {
		var ret bool
		return ret
	}
	return *o.UseColumnNamesAsPropertyNames
}

// GetUseColumnNamesAsPropertyNamesOk returns a tuple with the UseColumnNamesAsPropertyNames field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DbIdentitySourceDTO) GetUseColumnNamesAsPropertyNamesOk() (*bool, bool) {
	if o == nil || isNil(o.UseColumnNamesAsPropertyNames) {
    return nil, false
	}
	return o.UseColumnNamesAsPropertyNames, true
}

// HasUseColumnNamesAsPropertyNames returns a boolean if a field has been set.
func (o *DbIdentitySourceDTO) HasUseColumnNamesAsPropertyNames() bool {
	if o != nil && !isNil(o.UseColumnNamesAsPropertyNames) {
		return true
	}

	return false
}

// SetUseColumnNamesAsPropertyNames gets a reference to the given bool and assigns it to the UseColumnNamesAsPropertyNames field.
func (o *DbIdentitySourceDTO) SetUseColumnNamesAsPropertyNames(v bool) {
	o.UseColumnNamesAsPropertyNames = &v
}

// GetUserPropertiesQueryString returns the UserPropertiesQueryString field value if set, zero value otherwise.
func (o *DbIdentitySourceDTO) GetUserPropertiesQueryString() string {
	if o == nil || isNil(o.UserPropertiesQueryString) {
		var ret string
		return ret
	}
	return *o.UserPropertiesQueryString
}

// GetUserPropertiesQueryStringOk returns a tuple with the UserPropertiesQueryString field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DbIdentitySourceDTO) GetUserPropertiesQueryStringOk() (*string, bool) {
	if o == nil || isNil(o.UserPropertiesQueryString) {
    return nil, false
	}
	return o.UserPropertiesQueryString, true
}

// HasUserPropertiesQueryString returns a boolean if a field has been set.
func (o *DbIdentitySourceDTO) HasUserPropertiesQueryString() bool {
	if o != nil && !isNil(o.UserPropertiesQueryString) {
		return true
	}

	return false
}

// SetUserPropertiesQueryString gets a reference to the given string and assigns it to the UserPropertiesQueryString field.
func (o *DbIdentitySourceDTO) SetUserPropertiesQueryString(v string) {
	o.UserPropertiesQueryString = &v
}

// GetUserQueryString returns the UserQueryString field value if set, zero value otherwise.
func (o *DbIdentitySourceDTO) GetUserQueryString() string {
	if o == nil || isNil(o.UserQueryString) {
		var ret string
		return ret
	}
	return *o.UserQueryString
}

// GetUserQueryStringOk returns a tuple with the UserQueryString field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DbIdentitySourceDTO) GetUserQueryStringOk() (*string, bool) {
	if o == nil || isNil(o.UserQueryString) {
    return nil, false
	}
	return o.UserQueryString, true
}

// HasUserQueryString returns a boolean if a field has been set.
func (o *DbIdentitySourceDTO) HasUserQueryString() bool {
	if o != nil && !isNil(o.UserQueryString) {
		return true
	}

	return false
}

// SetUserQueryString gets a reference to the given string and assigns it to the UserQueryString field.
func (o *DbIdentitySourceDTO) SetUserQueryString(v string) {
	o.UserQueryString = &v
}

// GetX returns the X field value if set, zero value otherwise.
func (o *DbIdentitySourceDTO) GetX() float64 {
	if o == nil || isNil(o.X) {
		var ret float64
		return ret
	}
	return *o.X
}

// GetXOk returns a tuple with the X field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DbIdentitySourceDTO) GetXOk() (*float64, bool) {
	if o == nil || isNil(o.X) {
    return nil, false
	}
	return o.X, true
}

// HasX returns a boolean if a field has been set.
func (o *DbIdentitySourceDTO) HasX() bool {
	if o != nil && !isNil(o.X) {
		return true
	}

	return false
}

// SetX gets a reference to the given float64 and assigns it to the X field.
func (o *DbIdentitySourceDTO) SetX(v float64) {
	o.X = &v
}

// GetY returns the Y field value if set, zero value otherwise.
func (o *DbIdentitySourceDTO) GetY() float64 {
	if o == nil || isNil(o.Y) {
		var ret float64
		return ret
	}
	return *o.Y
}

// GetYOk returns a tuple with the Y field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DbIdentitySourceDTO) GetYOk() (*float64, bool) {
	if o == nil || isNil(o.Y) {
    return nil, false
	}
	return o.Y, true
}

// HasY returns a boolean if a field has been set.
func (o *DbIdentitySourceDTO) HasY() bool {
	if o != nil && !isNil(o.Y) {
		return true
	}

	return false
}

// SetY gets a reference to the given float64 and assigns it to the Y field.
func (o *DbIdentitySourceDTO) SetY(v float64) {
	o.Y = &v
}

func (o DbIdentitySourceDTO) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if !isNil(o.AcquireIncrement) {
		toSerialize["acquireIncrement"] = o.AcquireIncrement
	}
	if !isNil(o.Admin) {
		toSerialize["admin"] = o.Admin
	}
	if !isNil(o.ConnectionUrl) {
		toSerialize["connectionUrl"] = o.ConnectionUrl
	}
	if !isNil(o.CredentialsQueryString) {
		toSerialize["credentialsQueryString"] = o.CredentialsQueryString
	}
	if !isNil(o.CustomClass) {
		toSerialize["customClass"] = o.CustomClass
	}
	if !isNil(o.Description) {
		toSerialize["description"] = o.Description
	}
	if !isNil(o.Driver) {
		toSerialize["driver"] = o.Driver
	}
	if !isNil(o.DriverName) {
		toSerialize["driverName"] = o.DriverName
	}
	if !isNil(o.ElementId) {
		toSerialize["elementId"] = o.ElementId
	}
	if !isNil(o.Id) {
		toSerialize["id"] = o.Id
	}
	if !isNil(o.IdleConnectionTestPeriod) {
		toSerialize["idleConnectionTestPeriod"] = o.IdleConnectionTestPeriod
	}
	if !isNil(o.InitialPoolSize) {
		toSerialize["initialPoolSize"] = o.InitialPoolSize
	}
	if !isNil(o.MaxIdleTime) {
		toSerialize["maxIdleTime"] = o.MaxIdleTime
	}
	if !isNil(o.MaxPoolSize) {
		toSerialize["maxPoolSize"] = o.MaxPoolSize
	}
	if !isNil(o.MinPoolSize) {
		toSerialize["minPoolSize"] = o.MinPoolSize
	}
	if !isNil(o.Name) {
		toSerialize["name"] = o.Name
	}
	if !isNil(o.Password) {
		toSerialize["password"] = o.Password
	}
	if !isNil(o.PooledDatasource) {
		toSerialize["pooledDatasource"] = o.PooledDatasource
	}
	if !isNil(o.RelayCredentialQueryString) {
		toSerialize["relayCredentialQueryString"] = o.RelayCredentialQueryString
	}
	if !isNil(o.ResetCredentialDml) {
		toSerialize["resetCredentialDml"] = o.ResetCredentialDml
	}
	if !isNil(o.RolesQueryString) {
		toSerialize["rolesQueryString"] = o.RolesQueryString
	}
	if !isNil(o.UseColumnNamesAsPropertyNames) {
		toSerialize["useColumnNamesAsPropertyNames"] = o.UseColumnNamesAsPropertyNames
	}
	if !isNil(o.UserPropertiesQueryString) {
		toSerialize["userPropertiesQueryString"] = o.UserPropertiesQueryString
	}
	if !isNil(o.UserQueryString) {
		toSerialize["userQueryString"] = o.UserQueryString
	}
	if !isNil(o.X) {
		toSerialize["x"] = o.X
	}
	if !isNil(o.Y) {
		toSerialize["y"] = o.Y
	}

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return json.Marshal(toSerialize)
}

func (o *DbIdentitySourceDTO) UnmarshalJSON(bytes []byte) (err error) {
	varDbIdentitySourceDTO := _DbIdentitySourceDTO{}

	if err = json.Unmarshal(bytes, &varDbIdentitySourceDTO); err == nil {
		*o = DbIdentitySourceDTO(varDbIdentitySourceDTO)
	}

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(bytes, &additionalProperties); err == nil {
		delete(additionalProperties, "acquireIncrement")
		delete(additionalProperties, "admin")
		delete(additionalProperties, "connectionUrl")
		delete(additionalProperties, "credentialsQueryString")
		delete(additionalProperties, "customClass")
		delete(additionalProperties, "description")
		delete(additionalProperties, "driver")
		delete(additionalProperties, "driverName")
		delete(additionalProperties, "elementId")
		delete(additionalProperties, "id")
		delete(additionalProperties, "idleConnectionTestPeriod")
		delete(additionalProperties, "initialPoolSize")
		delete(additionalProperties, "maxIdleTime")
		delete(additionalProperties, "maxPoolSize")
		delete(additionalProperties, "minPoolSize")
		delete(additionalProperties, "name")
		delete(additionalProperties, "password")
		delete(additionalProperties, "pooledDatasource")
		delete(additionalProperties, "relayCredentialQueryString")
		delete(additionalProperties, "resetCredentialDml")
		delete(additionalProperties, "rolesQueryString")
		delete(additionalProperties, "useColumnNamesAsPropertyNames")
		delete(additionalProperties, "userPropertiesQueryString")
		delete(additionalProperties, "userQueryString")
		delete(additionalProperties, "x")
		delete(additionalProperties, "y")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableDbIdentitySourceDTO struct {
	value *DbIdentitySourceDTO
	isSet bool
}

func (v NullableDbIdentitySourceDTO) Get() *DbIdentitySourceDTO {
	return v.value
}

func (v *NullableDbIdentitySourceDTO) Set(val *DbIdentitySourceDTO) {
	v.value = val
	v.isSet = true
}

func (v NullableDbIdentitySourceDTO) IsSet() bool {
	return v.isSet
}

func (v *NullableDbIdentitySourceDTO) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableDbIdentitySourceDTO(val *DbIdentitySourceDTO) *NullableDbIdentitySourceDTO {
	return &NullableDbIdentitySourceDTO{value: val, isSet: true}
}

func (v NullableDbIdentitySourceDTO) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableDbIdentitySourceDTO) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


