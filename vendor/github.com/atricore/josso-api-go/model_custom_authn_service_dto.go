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

// CustomAuthnServiceDTO struct for CustomAuthnServiceDTO
type CustomAuthnServiceDTO struct {
	AuthnCtxClass *string `json:"authnCtxClass,omitempty"`
	AuthnMechanismType *string `json:"authnMechanismType,omitempty"`
	CustomClass *CustomClassDTO `json:"customClass,omitempty"`
	DelegatedAuthentications []DelegatedAuthenticationDTO `json:"delegatedAuthentications,omitempty"`
	Description *string `json:"description,omitempty"`
	DisplayName *string `json:"displayName,omitempty"`
	ElementId *string `json:"elementId,omitempty"`
	Id *int64 `json:"id,omitempty"`
	Name *string `json:"name,omitempty"`
	PreAuthnClaimCollectorConfig *string `json:"preAuthnClaimCollectorConfig,omitempty"`
	PreAuthnClaimCollectorType *string `json:"preAuthnClaimCollectorType,omitempty"`
	PreAuthnServiceURL *string `json:"preAuthnServiceURL,omitempty"`
	UseCredentialStore *bool `json:"useCredentialStore,omitempty"`
	X *float64 `json:"x,omitempty"`
	Y *float64 `json:"y,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _CustomAuthnServiceDTO CustomAuthnServiceDTO

// NewCustomAuthnServiceDTO instantiates a new CustomAuthnServiceDTO object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCustomAuthnServiceDTO() *CustomAuthnServiceDTO {
	this := CustomAuthnServiceDTO{}
	return &this
}

// NewCustomAuthnServiceDTOWithDefaults instantiates a new CustomAuthnServiceDTO object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCustomAuthnServiceDTOWithDefaults() *CustomAuthnServiceDTO {
	this := CustomAuthnServiceDTO{}
	return &this
}

// GetAuthnCtxClass returns the AuthnCtxClass field value if set, zero value otherwise.
func (o *CustomAuthnServiceDTO) GetAuthnCtxClass() string {
	if o == nil || isNil(o.AuthnCtxClass) {
		var ret string
		return ret
	}
	return *o.AuthnCtxClass
}

// GetAuthnCtxClassOk returns a tuple with the AuthnCtxClass field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustomAuthnServiceDTO) GetAuthnCtxClassOk() (*string, bool) {
	if o == nil || isNil(o.AuthnCtxClass) {
    return nil, false
	}
	return o.AuthnCtxClass, true
}

// HasAuthnCtxClass returns a boolean if a field has been set.
func (o *CustomAuthnServiceDTO) HasAuthnCtxClass() bool {
	if o != nil && !isNil(o.AuthnCtxClass) {
		return true
	}

	return false
}

// SetAuthnCtxClass gets a reference to the given string and assigns it to the AuthnCtxClass field.
func (o *CustomAuthnServiceDTO) SetAuthnCtxClass(v string) {
	o.AuthnCtxClass = &v
}

// GetAuthnMechanismType returns the AuthnMechanismType field value if set, zero value otherwise.
func (o *CustomAuthnServiceDTO) GetAuthnMechanismType() string {
	if o == nil || isNil(o.AuthnMechanismType) {
		var ret string
		return ret
	}
	return *o.AuthnMechanismType
}

// GetAuthnMechanismTypeOk returns a tuple with the AuthnMechanismType field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustomAuthnServiceDTO) GetAuthnMechanismTypeOk() (*string, bool) {
	if o == nil || isNil(o.AuthnMechanismType) {
    return nil, false
	}
	return o.AuthnMechanismType, true
}

// HasAuthnMechanismType returns a boolean if a field has been set.
func (o *CustomAuthnServiceDTO) HasAuthnMechanismType() bool {
	if o != nil && !isNil(o.AuthnMechanismType) {
		return true
	}

	return false
}

// SetAuthnMechanismType gets a reference to the given string and assigns it to the AuthnMechanismType field.
func (o *CustomAuthnServiceDTO) SetAuthnMechanismType(v string) {
	o.AuthnMechanismType = &v
}

// GetCustomClass returns the CustomClass field value if set, zero value otherwise.
func (o *CustomAuthnServiceDTO) GetCustomClass() CustomClassDTO {
	if o == nil || isNil(o.CustomClass) {
		var ret CustomClassDTO
		return ret
	}
	return *o.CustomClass
}

// GetCustomClassOk returns a tuple with the CustomClass field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustomAuthnServiceDTO) GetCustomClassOk() (*CustomClassDTO, bool) {
	if o == nil || isNil(o.CustomClass) {
    return nil, false
	}
	return o.CustomClass, true
}

// HasCustomClass returns a boolean if a field has been set.
func (o *CustomAuthnServiceDTO) HasCustomClass() bool {
	if o != nil && !isNil(o.CustomClass) {
		return true
	}

	return false
}

// SetCustomClass gets a reference to the given CustomClassDTO and assigns it to the CustomClass field.
func (o *CustomAuthnServiceDTO) SetCustomClass(v CustomClassDTO) {
	o.CustomClass = &v
}

// GetDelegatedAuthentications returns the DelegatedAuthentications field value if set, zero value otherwise.
func (o *CustomAuthnServiceDTO) GetDelegatedAuthentications() []DelegatedAuthenticationDTO {
	if o == nil || isNil(o.DelegatedAuthentications) {
		var ret []DelegatedAuthenticationDTO
		return ret
	}
	return o.DelegatedAuthentications
}

// GetDelegatedAuthenticationsOk returns a tuple with the DelegatedAuthentications field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustomAuthnServiceDTO) GetDelegatedAuthenticationsOk() ([]DelegatedAuthenticationDTO, bool) {
	if o == nil || isNil(o.DelegatedAuthentications) {
    return nil, false
	}
	return o.DelegatedAuthentications, true
}

// HasDelegatedAuthentications returns a boolean if a field has been set.
func (o *CustomAuthnServiceDTO) HasDelegatedAuthentications() bool {
	if o != nil && !isNil(o.DelegatedAuthentications) {
		return true
	}

	return false
}

// SetDelegatedAuthentications gets a reference to the given []DelegatedAuthenticationDTO and assigns it to the DelegatedAuthentications field.
func (o *CustomAuthnServiceDTO) SetDelegatedAuthentications(v []DelegatedAuthenticationDTO) {
	o.DelegatedAuthentications = v
}

// GetDescription returns the Description field value if set, zero value otherwise.
func (o *CustomAuthnServiceDTO) GetDescription() string {
	if o == nil || isNil(o.Description) {
		var ret string
		return ret
	}
	return *o.Description
}

// GetDescriptionOk returns a tuple with the Description field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustomAuthnServiceDTO) GetDescriptionOk() (*string, bool) {
	if o == nil || isNil(o.Description) {
    return nil, false
	}
	return o.Description, true
}

// HasDescription returns a boolean if a field has been set.
func (o *CustomAuthnServiceDTO) HasDescription() bool {
	if o != nil && !isNil(o.Description) {
		return true
	}

	return false
}

// SetDescription gets a reference to the given string and assigns it to the Description field.
func (o *CustomAuthnServiceDTO) SetDescription(v string) {
	o.Description = &v
}

// GetDisplayName returns the DisplayName field value if set, zero value otherwise.
func (o *CustomAuthnServiceDTO) GetDisplayName() string {
	if o == nil || isNil(o.DisplayName) {
		var ret string
		return ret
	}
	return *o.DisplayName
}

// GetDisplayNameOk returns a tuple with the DisplayName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustomAuthnServiceDTO) GetDisplayNameOk() (*string, bool) {
	if o == nil || isNil(o.DisplayName) {
    return nil, false
	}
	return o.DisplayName, true
}

// HasDisplayName returns a boolean if a field has been set.
func (o *CustomAuthnServiceDTO) HasDisplayName() bool {
	if o != nil && !isNil(o.DisplayName) {
		return true
	}

	return false
}

// SetDisplayName gets a reference to the given string and assigns it to the DisplayName field.
func (o *CustomAuthnServiceDTO) SetDisplayName(v string) {
	o.DisplayName = &v
}

// GetElementId returns the ElementId field value if set, zero value otherwise.
func (o *CustomAuthnServiceDTO) GetElementId() string {
	if o == nil || isNil(o.ElementId) {
		var ret string
		return ret
	}
	return *o.ElementId
}

// GetElementIdOk returns a tuple with the ElementId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustomAuthnServiceDTO) GetElementIdOk() (*string, bool) {
	if o == nil || isNil(o.ElementId) {
    return nil, false
	}
	return o.ElementId, true
}

// HasElementId returns a boolean if a field has been set.
func (o *CustomAuthnServiceDTO) HasElementId() bool {
	if o != nil && !isNil(o.ElementId) {
		return true
	}

	return false
}

// SetElementId gets a reference to the given string and assigns it to the ElementId field.
func (o *CustomAuthnServiceDTO) SetElementId(v string) {
	o.ElementId = &v
}

// GetId returns the Id field value if set, zero value otherwise.
func (o *CustomAuthnServiceDTO) GetId() int64 {
	if o == nil || isNil(o.Id) {
		var ret int64
		return ret
	}
	return *o.Id
}

// GetIdOk returns a tuple with the Id field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustomAuthnServiceDTO) GetIdOk() (*int64, bool) {
	if o == nil || isNil(o.Id) {
    return nil, false
	}
	return o.Id, true
}

// HasId returns a boolean if a field has been set.
func (o *CustomAuthnServiceDTO) HasId() bool {
	if o != nil && !isNil(o.Id) {
		return true
	}

	return false
}

// SetId gets a reference to the given int64 and assigns it to the Id field.
func (o *CustomAuthnServiceDTO) SetId(v int64) {
	o.Id = &v
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *CustomAuthnServiceDTO) GetName() string {
	if o == nil || isNil(o.Name) {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustomAuthnServiceDTO) GetNameOk() (*string, bool) {
	if o == nil || isNil(o.Name) {
    return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *CustomAuthnServiceDTO) HasName() bool {
	if o != nil && !isNil(o.Name) {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *CustomAuthnServiceDTO) SetName(v string) {
	o.Name = &v
}

// GetPreAuthnClaimCollectorConfig returns the PreAuthnClaimCollectorConfig field value if set, zero value otherwise.
func (o *CustomAuthnServiceDTO) GetPreAuthnClaimCollectorConfig() string {
	if o == nil || isNil(o.PreAuthnClaimCollectorConfig) {
		var ret string
		return ret
	}
	return *o.PreAuthnClaimCollectorConfig
}

// GetPreAuthnClaimCollectorConfigOk returns a tuple with the PreAuthnClaimCollectorConfig field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustomAuthnServiceDTO) GetPreAuthnClaimCollectorConfigOk() (*string, bool) {
	if o == nil || isNil(o.PreAuthnClaimCollectorConfig) {
    return nil, false
	}
	return o.PreAuthnClaimCollectorConfig, true
}

// HasPreAuthnClaimCollectorConfig returns a boolean if a field has been set.
func (o *CustomAuthnServiceDTO) HasPreAuthnClaimCollectorConfig() bool {
	if o != nil && !isNil(o.PreAuthnClaimCollectorConfig) {
		return true
	}

	return false
}

// SetPreAuthnClaimCollectorConfig gets a reference to the given string and assigns it to the PreAuthnClaimCollectorConfig field.
func (o *CustomAuthnServiceDTO) SetPreAuthnClaimCollectorConfig(v string) {
	o.PreAuthnClaimCollectorConfig = &v
}

// GetPreAuthnClaimCollectorType returns the PreAuthnClaimCollectorType field value if set, zero value otherwise.
func (o *CustomAuthnServiceDTO) GetPreAuthnClaimCollectorType() string {
	if o == nil || isNil(o.PreAuthnClaimCollectorType) {
		var ret string
		return ret
	}
	return *o.PreAuthnClaimCollectorType
}

// GetPreAuthnClaimCollectorTypeOk returns a tuple with the PreAuthnClaimCollectorType field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustomAuthnServiceDTO) GetPreAuthnClaimCollectorTypeOk() (*string, bool) {
	if o == nil || isNil(o.PreAuthnClaimCollectorType) {
    return nil, false
	}
	return o.PreAuthnClaimCollectorType, true
}

// HasPreAuthnClaimCollectorType returns a boolean if a field has been set.
func (o *CustomAuthnServiceDTO) HasPreAuthnClaimCollectorType() bool {
	if o != nil && !isNil(o.PreAuthnClaimCollectorType) {
		return true
	}

	return false
}

// SetPreAuthnClaimCollectorType gets a reference to the given string and assigns it to the PreAuthnClaimCollectorType field.
func (o *CustomAuthnServiceDTO) SetPreAuthnClaimCollectorType(v string) {
	o.PreAuthnClaimCollectorType = &v
}

// GetPreAuthnServiceURL returns the PreAuthnServiceURL field value if set, zero value otherwise.
func (o *CustomAuthnServiceDTO) GetPreAuthnServiceURL() string {
	if o == nil || isNil(o.PreAuthnServiceURL) {
		var ret string
		return ret
	}
	return *o.PreAuthnServiceURL
}

// GetPreAuthnServiceURLOk returns a tuple with the PreAuthnServiceURL field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustomAuthnServiceDTO) GetPreAuthnServiceURLOk() (*string, bool) {
	if o == nil || isNil(o.PreAuthnServiceURL) {
    return nil, false
	}
	return o.PreAuthnServiceURL, true
}

// HasPreAuthnServiceURL returns a boolean if a field has been set.
func (o *CustomAuthnServiceDTO) HasPreAuthnServiceURL() bool {
	if o != nil && !isNil(o.PreAuthnServiceURL) {
		return true
	}

	return false
}

// SetPreAuthnServiceURL gets a reference to the given string and assigns it to the PreAuthnServiceURL field.
func (o *CustomAuthnServiceDTO) SetPreAuthnServiceURL(v string) {
	o.PreAuthnServiceURL = &v
}

// GetUseCredentialStore returns the UseCredentialStore field value if set, zero value otherwise.
func (o *CustomAuthnServiceDTO) GetUseCredentialStore() bool {
	if o == nil || isNil(o.UseCredentialStore) {
		var ret bool
		return ret
	}
	return *o.UseCredentialStore
}

// GetUseCredentialStoreOk returns a tuple with the UseCredentialStore field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustomAuthnServiceDTO) GetUseCredentialStoreOk() (*bool, bool) {
	if o == nil || isNil(o.UseCredentialStore) {
    return nil, false
	}
	return o.UseCredentialStore, true
}

// HasUseCredentialStore returns a boolean if a field has been set.
func (o *CustomAuthnServiceDTO) HasUseCredentialStore() bool {
	if o != nil && !isNil(o.UseCredentialStore) {
		return true
	}

	return false
}

// SetUseCredentialStore gets a reference to the given bool and assigns it to the UseCredentialStore field.
func (o *CustomAuthnServiceDTO) SetUseCredentialStore(v bool) {
	o.UseCredentialStore = &v
}

// GetX returns the X field value if set, zero value otherwise.
func (o *CustomAuthnServiceDTO) GetX() float64 {
	if o == nil || isNil(o.X) {
		var ret float64
		return ret
	}
	return *o.X
}

// GetXOk returns a tuple with the X field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustomAuthnServiceDTO) GetXOk() (*float64, bool) {
	if o == nil || isNil(o.X) {
    return nil, false
	}
	return o.X, true
}

// HasX returns a boolean if a field has been set.
func (o *CustomAuthnServiceDTO) HasX() bool {
	if o != nil && !isNil(o.X) {
		return true
	}

	return false
}

// SetX gets a reference to the given float64 and assigns it to the X field.
func (o *CustomAuthnServiceDTO) SetX(v float64) {
	o.X = &v
}

// GetY returns the Y field value if set, zero value otherwise.
func (o *CustomAuthnServiceDTO) GetY() float64 {
	if o == nil || isNil(o.Y) {
		var ret float64
		return ret
	}
	return *o.Y
}

// GetYOk returns a tuple with the Y field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustomAuthnServiceDTO) GetYOk() (*float64, bool) {
	if o == nil || isNil(o.Y) {
    return nil, false
	}
	return o.Y, true
}

// HasY returns a boolean if a field has been set.
func (o *CustomAuthnServiceDTO) HasY() bool {
	if o != nil && !isNil(o.Y) {
		return true
	}

	return false
}

// SetY gets a reference to the given float64 and assigns it to the Y field.
func (o *CustomAuthnServiceDTO) SetY(v float64) {
	o.Y = &v
}

func (o CustomAuthnServiceDTO) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if !isNil(o.AuthnCtxClass) {
		toSerialize["authnCtxClass"] = o.AuthnCtxClass
	}
	if !isNil(o.AuthnMechanismType) {
		toSerialize["authnMechanismType"] = o.AuthnMechanismType
	}
	if !isNil(o.CustomClass) {
		toSerialize["customClass"] = o.CustomClass
	}
	if !isNil(o.DelegatedAuthentications) {
		toSerialize["delegatedAuthentications"] = o.DelegatedAuthentications
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
	if !isNil(o.Name) {
		toSerialize["name"] = o.Name
	}
	if !isNil(o.PreAuthnClaimCollectorConfig) {
		toSerialize["preAuthnClaimCollectorConfig"] = o.PreAuthnClaimCollectorConfig
	}
	if !isNil(o.PreAuthnClaimCollectorType) {
		toSerialize["preAuthnClaimCollectorType"] = o.PreAuthnClaimCollectorType
	}
	if !isNil(o.PreAuthnServiceURL) {
		toSerialize["preAuthnServiceURL"] = o.PreAuthnServiceURL
	}
	if !isNil(o.UseCredentialStore) {
		toSerialize["useCredentialStore"] = o.UseCredentialStore
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

func (o *CustomAuthnServiceDTO) UnmarshalJSON(bytes []byte) (err error) {
	varCustomAuthnServiceDTO := _CustomAuthnServiceDTO{}

	if err = json.Unmarshal(bytes, &varCustomAuthnServiceDTO); err == nil {
		*o = CustomAuthnServiceDTO(varCustomAuthnServiceDTO)
	}

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(bytes, &additionalProperties); err == nil {
		delete(additionalProperties, "authnCtxClass")
		delete(additionalProperties, "authnMechanismType")
		delete(additionalProperties, "customClass")
		delete(additionalProperties, "delegatedAuthentications")
		delete(additionalProperties, "description")
		delete(additionalProperties, "displayName")
		delete(additionalProperties, "elementId")
		delete(additionalProperties, "id")
		delete(additionalProperties, "name")
		delete(additionalProperties, "preAuthnClaimCollectorConfig")
		delete(additionalProperties, "preAuthnClaimCollectorType")
		delete(additionalProperties, "preAuthnServiceURL")
		delete(additionalProperties, "useCredentialStore")
		delete(additionalProperties, "x")
		delete(additionalProperties, "y")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableCustomAuthnServiceDTO struct {
	value *CustomAuthnServiceDTO
	isSet bool
}

func (v NullableCustomAuthnServiceDTO) Get() *CustomAuthnServiceDTO {
	return v.value
}

func (v *NullableCustomAuthnServiceDTO) Set(val *CustomAuthnServiceDTO) {
	v.value = val
	v.isSet = true
}

func (v NullableCustomAuthnServiceDTO) IsSet() bool {
	return v.isSet
}

func (v *NullableCustomAuthnServiceDTO) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCustomAuthnServiceDTO(val *CustomAuthnServiceDTO) *NullableCustomAuthnServiceDTO {
	return &NullableCustomAuthnServiceDTO{value: val, isSet: true}
}

func (v NullableCustomAuthnServiceDTO) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCustomAuthnServiceDTO) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

