/*
Atricore Console :: Remote : API

# Atricore Console API

API version: 1.5.1-SNAPSHOT
Contact: sgonzalez@atricore.com
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package jossoappi

import (
	"encoding/json"
)

// FederatedProviderDTO struct for FederatedProviderDTO
type FederatedProviderDTO struct {
	ActiveBindings []string `json:"activeBindings,omitempty"`
	ActiveProfiles []string `json:"activeProfiles,omitempty"`
	Config *ProviderConfigDTO `json:"config,omitempty"`
	Description *string `json:"description,omitempty"`
	DisplayName *string `json:"displayName,omitempty"`
	ElementId *string `json:"elementId,omitempty"`
	Id *int64 `json:"id,omitempty"`
	IdentityAppliance *IdentityApplianceDefinitionDTO `json:"identityAppliance,omitempty"`
	IsRemote *bool `json:"isRemote,omitempty"`
	Location *LocationDTO `json:"location,omitempty"`
	Metadata *ResourceDTO `json:"metadata,omitempty"`
	Name *string `json:"name,omitempty"`
	Remote *bool `json:"remote,omitempty"`
	Role *string `json:"role,omitempty"`
	X *float64 `json:"x,omitempty"`
	Y *float64 `json:"y,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _FederatedProviderDTO FederatedProviderDTO

// NewFederatedProviderDTO instantiates a new FederatedProviderDTO object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewFederatedProviderDTO() *FederatedProviderDTO {
	this := FederatedProviderDTO{}
	return &this
}

// NewFederatedProviderDTOWithDefaults instantiates a new FederatedProviderDTO object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewFederatedProviderDTOWithDefaults() *FederatedProviderDTO {
	this := FederatedProviderDTO{}
	return &this
}

// GetActiveBindings returns the ActiveBindings field value if set, zero value otherwise.
func (o *FederatedProviderDTO) GetActiveBindings() []string {
	if o == nil || isNil(o.ActiveBindings) {
		var ret []string
		return ret
	}
	return o.ActiveBindings
}

// GetActiveBindingsOk returns a tuple with the ActiveBindings field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FederatedProviderDTO) GetActiveBindingsOk() ([]string, bool) {
	if o == nil || isNil(o.ActiveBindings) {
    return nil, false
	}
	return o.ActiveBindings, true
}

// HasActiveBindings returns a boolean if a field has been set.
func (o *FederatedProviderDTO) HasActiveBindings() bool {
	if o != nil && !isNil(o.ActiveBindings) {
		return true
	}

	return false
}

// SetActiveBindings gets a reference to the given []string and assigns it to the ActiveBindings field.
func (o *FederatedProviderDTO) SetActiveBindings(v []string) {
	o.ActiveBindings = v
}

// GetActiveProfiles returns the ActiveProfiles field value if set, zero value otherwise.
func (o *FederatedProviderDTO) GetActiveProfiles() []string {
	if o == nil || isNil(o.ActiveProfiles) {
		var ret []string
		return ret
	}
	return o.ActiveProfiles
}

// GetActiveProfilesOk returns a tuple with the ActiveProfiles field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FederatedProviderDTO) GetActiveProfilesOk() ([]string, bool) {
	if o == nil || isNil(o.ActiveProfiles) {
    return nil, false
	}
	return o.ActiveProfiles, true
}

// HasActiveProfiles returns a boolean if a field has been set.
func (o *FederatedProviderDTO) HasActiveProfiles() bool {
	if o != nil && !isNil(o.ActiveProfiles) {
		return true
	}

	return false
}

// SetActiveProfiles gets a reference to the given []string and assigns it to the ActiveProfiles field.
func (o *FederatedProviderDTO) SetActiveProfiles(v []string) {
	o.ActiveProfiles = v
}

// GetConfig returns the Config field value if set, zero value otherwise.
func (o *FederatedProviderDTO) GetConfig() ProviderConfigDTO {
	if o == nil || isNil(o.Config) {
		var ret ProviderConfigDTO
		return ret
	}
	return *o.Config
}

// GetConfigOk returns a tuple with the Config field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FederatedProviderDTO) GetConfigOk() (*ProviderConfigDTO, bool) {
	if o == nil || isNil(o.Config) {
    return nil, false
	}
	return o.Config, true
}

// HasConfig returns a boolean if a field has been set.
func (o *FederatedProviderDTO) HasConfig() bool {
	if o != nil && !isNil(o.Config) {
		return true
	}

	return false
}

// SetConfig gets a reference to the given ProviderConfigDTO and assigns it to the Config field.
func (o *FederatedProviderDTO) SetConfig(v ProviderConfigDTO) {
	o.Config = &v
}

// GetDescription returns the Description field value if set, zero value otherwise.
func (o *FederatedProviderDTO) GetDescription() string {
	if o == nil || isNil(o.Description) {
		var ret string
		return ret
	}
	return *o.Description
}

// GetDescriptionOk returns a tuple with the Description field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FederatedProviderDTO) GetDescriptionOk() (*string, bool) {
	if o == nil || isNil(o.Description) {
    return nil, false
	}
	return o.Description, true
}

// HasDescription returns a boolean if a field has been set.
func (o *FederatedProviderDTO) HasDescription() bool {
	if o != nil && !isNil(o.Description) {
		return true
	}

	return false
}

// SetDescription gets a reference to the given string and assigns it to the Description field.
func (o *FederatedProviderDTO) SetDescription(v string) {
	o.Description = &v
}

// GetDisplayName returns the DisplayName field value if set, zero value otherwise.
func (o *FederatedProviderDTO) GetDisplayName() string {
	if o == nil || isNil(o.DisplayName) {
		var ret string
		return ret
	}
	return *o.DisplayName
}

// GetDisplayNameOk returns a tuple with the DisplayName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FederatedProviderDTO) GetDisplayNameOk() (*string, bool) {
	if o == nil || isNil(o.DisplayName) {
    return nil, false
	}
	return o.DisplayName, true
}

// HasDisplayName returns a boolean if a field has been set.
func (o *FederatedProviderDTO) HasDisplayName() bool {
	if o != nil && !isNil(o.DisplayName) {
		return true
	}

	return false
}

// SetDisplayName gets a reference to the given string and assigns it to the DisplayName field.
func (o *FederatedProviderDTO) SetDisplayName(v string) {
	o.DisplayName = &v
}

// GetElementId returns the ElementId field value if set, zero value otherwise.
func (o *FederatedProviderDTO) GetElementId() string {
	if o == nil || isNil(o.ElementId) {
		var ret string
		return ret
	}
	return *o.ElementId
}

// GetElementIdOk returns a tuple with the ElementId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FederatedProviderDTO) GetElementIdOk() (*string, bool) {
	if o == nil || isNil(o.ElementId) {
    return nil, false
	}
	return o.ElementId, true
}

// HasElementId returns a boolean if a field has been set.
func (o *FederatedProviderDTO) HasElementId() bool {
	if o != nil && !isNil(o.ElementId) {
		return true
	}

	return false
}

// SetElementId gets a reference to the given string and assigns it to the ElementId field.
func (o *FederatedProviderDTO) SetElementId(v string) {
	o.ElementId = &v
}

// GetId returns the Id field value if set, zero value otherwise.
func (o *FederatedProviderDTO) GetId() int64 {
	if o == nil || isNil(o.Id) {
		var ret int64
		return ret
	}
	return *o.Id
}

// GetIdOk returns a tuple with the Id field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FederatedProviderDTO) GetIdOk() (*int64, bool) {
	if o == nil || isNil(o.Id) {
    return nil, false
	}
	return o.Id, true
}

// HasId returns a boolean if a field has been set.
func (o *FederatedProviderDTO) HasId() bool {
	if o != nil && !isNil(o.Id) {
		return true
	}

	return false
}

// SetId gets a reference to the given int64 and assigns it to the Id field.
func (o *FederatedProviderDTO) SetId(v int64) {
	o.Id = &v
}

// GetIdentityAppliance returns the IdentityAppliance field value if set, zero value otherwise.
func (o *FederatedProviderDTO) GetIdentityAppliance() IdentityApplianceDefinitionDTO {
	if o == nil || isNil(o.IdentityAppliance) {
		var ret IdentityApplianceDefinitionDTO
		return ret
	}
	return *o.IdentityAppliance
}

// GetIdentityApplianceOk returns a tuple with the IdentityAppliance field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FederatedProviderDTO) GetIdentityApplianceOk() (*IdentityApplianceDefinitionDTO, bool) {
	if o == nil || isNil(o.IdentityAppliance) {
    return nil, false
	}
	return o.IdentityAppliance, true
}

// HasIdentityAppliance returns a boolean if a field has been set.
func (o *FederatedProviderDTO) HasIdentityAppliance() bool {
	if o != nil && !isNil(o.IdentityAppliance) {
		return true
	}

	return false
}

// SetIdentityAppliance gets a reference to the given IdentityApplianceDefinitionDTO and assigns it to the IdentityAppliance field.
func (o *FederatedProviderDTO) SetIdentityAppliance(v IdentityApplianceDefinitionDTO) {
	o.IdentityAppliance = &v
}

// GetIsRemote returns the IsRemote field value if set, zero value otherwise.
func (o *FederatedProviderDTO) GetIsRemote() bool {
	if o == nil || isNil(o.IsRemote) {
		var ret bool
		return ret
	}
	return *o.IsRemote
}

// GetIsRemoteOk returns a tuple with the IsRemote field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FederatedProviderDTO) GetIsRemoteOk() (*bool, bool) {
	if o == nil || isNil(o.IsRemote) {
    return nil, false
	}
	return o.IsRemote, true
}

// HasIsRemote returns a boolean if a field has been set.
func (o *FederatedProviderDTO) HasIsRemote() bool {
	if o != nil && !isNil(o.IsRemote) {
		return true
	}

	return false
}

// SetIsRemote gets a reference to the given bool and assigns it to the IsRemote field.
func (o *FederatedProviderDTO) SetIsRemote(v bool) {
	o.IsRemote = &v
}

// GetLocation returns the Location field value if set, zero value otherwise.
func (o *FederatedProviderDTO) GetLocation() LocationDTO {
	if o == nil || isNil(o.Location) {
		var ret LocationDTO
		return ret
	}
	return *o.Location
}

// GetLocationOk returns a tuple with the Location field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FederatedProviderDTO) GetLocationOk() (*LocationDTO, bool) {
	if o == nil || isNil(o.Location) {
    return nil, false
	}
	return o.Location, true
}

// HasLocation returns a boolean if a field has been set.
func (o *FederatedProviderDTO) HasLocation() bool {
	if o != nil && !isNil(o.Location) {
		return true
	}

	return false
}

// SetLocation gets a reference to the given LocationDTO and assigns it to the Location field.
func (o *FederatedProviderDTO) SetLocation(v LocationDTO) {
	o.Location = &v
}

// GetMetadata returns the Metadata field value if set, zero value otherwise.
func (o *FederatedProviderDTO) GetMetadata() ResourceDTO {
	if o == nil || isNil(o.Metadata) {
		var ret ResourceDTO
		return ret
	}
	return *o.Metadata
}

// GetMetadataOk returns a tuple with the Metadata field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FederatedProviderDTO) GetMetadataOk() (*ResourceDTO, bool) {
	if o == nil || isNil(o.Metadata) {
    return nil, false
	}
	return o.Metadata, true
}

// HasMetadata returns a boolean if a field has been set.
func (o *FederatedProviderDTO) HasMetadata() bool {
	if o != nil && !isNil(o.Metadata) {
		return true
	}

	return false
}

// SetMetadata gets a reference to the given ResourceDTO and assigns it to the Metadata field.
func (o *FederatedProviderDTO) SetMetadata(v ResourceDTO) {
	o.Metadata = &v
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *FederatedProviderDTO) GetName() string {
	if o == nil || isNil(o.Name) {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FederatedProviderDTO) GetNameOk() (*string, bool) {
	if o == nil || isNil(o.Name) {
    return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *FederatedProviderDTO) HasName() bool {
	if o != nil && !isNil(o.Name) {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *FederatedProviderDTO) SetName(v string) {
	o.Name = &v
}

// GetRemote returns the Remote field value if set, zero value otherwise.
func (o *FederatedProviderDTO) GetRemote() bool {
	if o == nil || isNil(o.Remote) {
		var ret bool
		return ret
	}
	return *o.Remote
}

// GetRemoteOk returns a tuple with the Remote field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FederatedProviderDTO) GetRemoteOk() (*bool, bool) {
	if o == nil || isNil(o.Remote) {
    return nil, false
	}
	return o.Remote, true
}

// HasRemote returns a boolean if a field has been set.
func (o *FederatedProviderDTO) HasRemote() bool {
	if o != nil && !isNil(o.Remote) {
		return true
	}

	return false
}

// SetRemote gets a reference to the given bool and assigns it to the Remote field.
func (o *FederatedProviderDTO) SetRemote(v bool) {
	o.Remote = &v
}

// GetRole returns the Role field value if set, zero value otherwise.
func (o *FederatedProviderDTO) GetRole() string {
	if o == nil || isNil(o.Role) {
		var ret string
		return ret
	}
	return *o.Role
}

// GetRoleOk returns a tuple with the Role field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FederatedProviderDTO) GetRoleOk() (*string, bool) {
	if o == nil || isNil(o.Role) {
    return nil, false
	}
	return o.Role, true
}

// HasRole returns a boolean if a field has been set.
func (o *FederatedProviderDTO) HasRole() bool {
	if o != nil && !isNil(o.Role) {
		return true
	}

	return false
}

// SetRole gets a reference to the given string and assigns it to the Role field.
func (o *FederatedProviderDTO) SetRole(v string) {
	o.Role = &v
}

// GetX returns the X field value if set, zero value otherwise.
func (o *FederatedProviderDTO) GetX() float64 {
	if o == nil || isNil(o.X) {
		var ret float64
		return ret
	}
	return *o.X
}

// GetXOk returns a tuple with the X field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FederatedProviderDTO) GetXOk() (*float64, bool) {
	if o == nil || isNil(o.X) {
    return nil, false
	}
	return o.X, true
}

// HasX returns a boolean if a field has been set.
func (o *FederatedProviderDTO) HasX() bool {
	if o != nil && !isNil(o.X) {
		return true
	}

	return false
}

// SetX gets a reference to the given float64 and assigns it to the X field.
func (o *FederatedProviderDTO) SetX(v float64) {
	o.X = &v
}

// GetY returns the Y field value if set, zero value otherwise.
func (o *FederatedProviderDTO) GetY() float64 {
	if o == nil || isNil(o.Y) {
		var ret float64
		return ret
	}
	return *o.Y
}

// GetYOk returns a tuple with the Y field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FederatedProviderDTO) GetYOk() (*float64, bool) {
	if o == nil || isNil(o.Y) {
    return nil, false
	}
	return o.Y, true
}

// HasY returns a boolean if a field has been set.
func (o *FederatedProviderDTO) HasY() bool {
	if o != nil && !isNil(o.Y) {
		return true
	}

	return false
}

// SetY gets a reference to the given float64 and assigns it to the Y field.
func (o *FederatedProviderDTO) SetY(v float64) {
	o.Y = &v
}

func (o FederatedProviderDTO) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if !isNil(o.ActiveBindings) {
		toSerialize["activeBindings"] = o.ActiveBindings
	}
	if !isNil(o.ActiveProfiles) {
		toSerialize["activeProfiles"] = o.ActiveProfiles
	}
	if !isNil(o.Config) {
		toSerialize["config"] = o.Config
	}
	if !isNil(o.Description) {
		toSerialize["description"] = o.Description
	}
	if !isNil(o.DisplayName) {
		toSerialize["displayName"] = o.DisplayName
	}
	if !isNil(o.ElementId) {
		toSerialize["elementId"] = o.ElementId
	}
	if !isNil(o.Id) {
		toSerialize["id"] = o.Id
	}
	if !isNil(o.IdentityAppliance) {
		toSerialize["identityAppliance"] = o.IdentityAppliance
	}
	if !isNil(o.IsRemote) {
		toSerialize["isRemote"] = o.IsRemote
	}
	if !isNil(o.Location) {
		toSerialize["location"] = o.Location
	}
	if !isNil(o.Metadata) {
		toSerialize["metadata"] = o.Metadata
	}
	if !isNil(o.Name) {
		toSerialize["name"] = o.Name
	}
	if !isNil(o.Remote) {
		toSerialize["remote"] = o.Remote
	}
	if !isNil(o.Role) {
		toSerialize["role"] = o.Role
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

func (o *FederatedProviderDTO) UnmarshalJSON(bytes []byte) (err error) {
	varFederatedProviderDTO := _FederatedProviderDTO{}

	if err = json.Unmarshal(bytes, &varFederatedProviderDTO); err == nil {
		*o = FederatedProviderDTO(varFederatedProviderDTO)
	}

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(bytes, &additionalProperties); err == nil {
		delete(additionalProperties, "activeBindings")
		delete(additionalProperties, "activeProfiles")
		delete(additionalProperties, "config")
		delete(additionalProperties, "description")
		delete(additionalProperties, "displayName")
		delete(additionalProperties, "elementId")
		delete(additionalProperties, "id")
		delete(additionalProperties, "identityAppliance")
		delete(additionalProperties, "isRemote")
		delete(additionalProperties, "location")
		delete(additionalProperties, "metadata")
		delete(additionalProperties, "name")
		delete(additionalProperties, "remote")
		delete(additionalProperties, "role")
		delete(additionalProperties, "x")
		delete(additionalProperties, "y")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableFederatedProviderDTO struct {
	value *FederatedProviderDTO
	isSet bool
}

func (v NullableFederatedProviderDTO) Get() *FederatedProviderDTO {
	return v.value
}

func (v *NullableFederatedProviderDTO) Set(val *FederatedProviderDTO) {
	v.value = val
	v.isSet = true
}

func (v NullableFederatedProviderDTO) IsSet() bool {
	return v.isSet
}

func (v *NullableFederatedProviderDTO) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableFederatedProviderDTO(val *FederatedProviderDTO) *NullableFederatedProviderDTO {
	return &NullableFederatedProviderDTO{value: val, isSet: true}
}

func (v NullableFederatedProviderDTO) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableFederatedProviderDTO) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


