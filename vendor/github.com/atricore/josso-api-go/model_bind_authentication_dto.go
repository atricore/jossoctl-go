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

// BindAuthenticationDTO struct for BindAuthenticationDTO
type BindAuthenticationDTO struct {
	DelegatedAuthentication *DelegatedAuthenticationDTO `json:"delegatedAuthentication,omitempty"`
	DisplayName *string `json:"displayName,omitempty"`
	ElementId *string `json:"elementId,omitempty"`
	Id *int64 `json:"id,omitempty"`
	Name *string `json:"name,omitempty"`
	Priority *int32 `json:"priority,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _BindAuthenticationDTO BindAuthenticationDTO

// NewBindAuthenticationDTO instantiates a new BindAuthenticationDTO object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewBindAuthenticationDTO() *BindAuthenticationDTO {
	this := BindAuthenticationDTO{}
	return &this
}

// NewBindAuthenticationDTOWithDefaults instantiates a new BindAuthenticationDTO object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewBindAuthenticationDTOWithDefaults() *BindAuthenticationDTO {
	this := BindAuthenticationDTO{}
	return &this
}

// GetDelegatedAuthentication returns the DelegatedAuthentication field value if set, zero value otherwise.
func (o *BindAuthenticationDTO) GetDelegatedAuthentication() DelegatedAuthenticationDTO {
	if o == nil || isNil(o.DelegatedAuthentication) {
		var ret DelegatedAuthenticationDTO
		return ret
	}
	return *o.DelegatedAuthentication
}

// GetDelegatedAuthenticationOk returns a tuple with the DelegatedAuthentication field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *BindAuthenticationDTO) GetDelegatedAuthenticationOk() (*DelegatedAuthenticationDTO, bool) {
	if o == nil || isNil(o.DelegatedAuthentication) {
    return nil, false
	}
	return o.DelegatedAuthentication, true
}

// HasDelegatedAuthentication returns a boolean if a field has been set.
func (o *BindAuthenticationDTO) HasDelegatedAuthentication() bool {
	if o != nil && !isNil(o.DelegatedAuthentication) {
		return true
	}

	return false
}

// SetDelegatedAuthentication gets a reference to the given DelegatedAuthenticationDTO and assigns it to the DelegatedAuthentication field.
func (o *BindAuthenticationDTO) SetDelegatedAuthentication(v DelegatedAuthenticationDTO) {
	o.DelegatedAuthentication = &v
}

// GetDisplayName returns the DisplayName field value if set, zero value otherwise.
func (o *BindAuthenticationDTO) GetDisplayName() string {
	if o == nil || isNil(o.DisplayName) {
		var ret string
		return ret
	}
	return *o.DisplayName
}

// GetDisplayNameOk returns a tuple with the DisplayName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *BindAuthenticationDTO) GetDisplayNameOk() (*string, bool) {
	if o == nil || isNil(o.DisplayName) {
    return nil, false
	}
	return o.DisplayName, true
}

// HasDisplayName returns a boolean if a field has been set.
func (o *BindAuthenticationDTO) HasDisplayName() bool {
	if o != nil && !isNil(o.DisplayName) {
		return true
	}

	return false
}

// SetDisplayName gets a reference to the given string and assigns it to the DisplayName field.
func (o *BindAuthenticationDTO) SetDisplayName(v string) {
	o.DisplayName = &v
}

// GetElementId returns the ElementId field value if set, zero value otherwise.
func (o *BindAuthenticationDTO) GetElementId() string {
	if o == nil || isNil(o.ElementId) {
		var ret string
		return ret
	}
	return *o.ElementId
}

// GetElementIdOk returns a tuple with the ElementId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *BindAuthenticationDTO) GetElementIdOk() (*string, bool) {
	if o == nil || isNil(o.ElementId) {
    return nil, false
	}
	return o.ElementId, true
}

// HasElementId returns a boolean if a field has been set.
func (o *BindAuthenticationDTO) HasElementId() bool {
	if o != nil && !isNil(o.ElementId) {
		return true
	}

	return false
}

// SetElementId gets a reference to the given string and assigns it to the ElementId field.
func (o *BindAuthenticationDTO) SetElementId(v string) {
	o.ElementId = &v
}

// GetId returns the Id field value if set, zero value otherwise.
func (o *BindAuthenticationDTO) GetId() int64 {
	if o == nil || isNil(o.Id) {
		var ret int64
		return ret
	}
	return *o.Id
}

// GetIdOk returns a tuple with the Id field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *BindAuthenticationDTO) GetIdOk() (*int64, bool) {
	if o == nil || isNil(o.Id) {
    return nil, false
	}
	return o.Id, true
}

// HasId returns a boolean if a field has been set.
func (o *BindAuthenticationDTO) HasId() bool {
	if o != nil && !isNil(o.Id) {
		return true
	}

	return false
}

// SetId gets a reference to the given int64 and assigns it to the Id field.
func (o *BindAuthenticationDTO) SetId(v int64) {
	o.Id = &v
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *BindAuthenticationDTO) GetName() string {
	if o == nil || isNil(o.Name) {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *BindAuthenticationDTO) GetNameOk() (*string, bool) {
	if o == nil || isNil(o.Name) {
    return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *BindAuthenticationDTO) HasName() bool {
	if o != nil && !isNil(o.Name) {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *BindAuthenticationDTO) SetName(v string) {
	o.Name = &v
}

// GetPriority returns the Priority field value if set, zero value otherwise.
func (o *BindAuthenticationDTO) GetPriority() int32 {
	if o == nil || isNil(o.Priority) {
		var ret int32
		return ret
	}
	return *o.Priority
}

// GetPriorityOk returns a tuple with the Priority field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *BindAuthenticationDTO) GetPriorityOk() (*int32, bool) {
	if o == nil || isNil(o.Priority) {
    return nil, false
	}
	return o.Priority, true
}

// HasPriority returns a boolean if a field has been set.
func (o *BindAuthenticationDTO) HasPriority() bool {
	if o != nil && !isNil(o.Priority) {
		return true
	}

	return false
}

// SetPriority gets a reference to the given int32 and assigns it to the Priority field.
func (o *BindAuthenticationDTO) SetPriority(v int32) {
	o.Priority = &v
}

func (o BindAuthenticationDTO) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if !isNil(o.DelegatedAuthentication) {
		toSerialize["delegatedAuthentication"] = o.DelegatedAuthentication
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
	if !isNil(o.Priority) {
		toSerialize["priority"] = o.Priority
	}

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return json.Marshal(toSerialize)
}

func (o *BindAuthenticationDTO) UnmarshalJSON(bytes []byte) (err error) {
	varBindAuthenticationDTO := _BindAuthenticationDTO{}

	if err = json.Unmarshal(bytes, &varBindAuthenticationDTO); err == nil {
		*o = BindAuthenticationDTO(varBindAuthenticationDTO)
	}

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(bytes, &additionalProperties); err == nil {
		delete(additionalProperties, "delegatedAuthentication")
		delete(additionalProperties, "displayName")
		delete(additionalProperties, "elementId")
		delete(additionalProperties, "id")
		delete(additionalProperties, "name")
		delete(additionalProperties, "priority")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableBindAuthenticationDTO struct {
	value *BindAuthenticationDTO
	isSet bool
}

func (v NullableBindAuthenticationDTO) Get() *BindAuthenticationDTO {
	return v.value
}

func (v *NullableBindAuthenticationDTO) Set(val *BindAuthenticationDTO) {
	v.value = val
	v.isSet = true
}

func (v NullableBindAuthenticationDTO) IsSet() bool {
	return v.isSet
}

func (v *NullableBindAuthenticationDTO) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableBindAuthenticationDTO(val *BindAuthenticationDTO) *NullableBindAuthenticationDTO {
	return &NullableBindAuthenticationDTO{value: val, isSet: true}
}

func (v NullableBindAuthenticationDTO) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableBindAuthenticationDTO) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

