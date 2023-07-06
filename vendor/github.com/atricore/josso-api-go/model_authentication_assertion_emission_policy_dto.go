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

// AuthenticationAssertionEmissionPolicyDTO struct for AuthenticationAssertionEmissionPolicyDTO
type AuthenticationAssertionEmissionPolicyDTO struct {
	ElementId *string `json:"elementId,omitempty"`
	Id *int64 `json:"id,omitempty"`
	Name *string `json:"name,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _AuthenticationAssertionEmissionPolicyDTO AuthenticationAssertionEmissionPolicyDTO

// NewAuthenticationAssertionEmissionPolicyDTO instantiates a new AuthenticationAssertionEmissionPolicyDTO object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAuthenticationAssertionEmissionPolicyDTO() *AuthenticationAssertionEmissionPolicyDTO {
	this := AuthenticationAssertionEmissionPolicyDTO{}
	return &this
}

// NewAuthenticationAssertionEmissionPolicyDTOWithDefaults instantiates a new AuthenticationAssertionEmissionPolicyDTO object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAuthenticationAssertionEmissionPolicyDTOWithDefaults() *AuthenticationAssertionEmissionPolicyDTO {
	this := AuthenticationAssertionEmissionPolicyDTO{}
	return &this
}

// GetElementId returns the ElementId field value if set, zero value otherwise.
func (o *AuthenticationAssertionEmissionPolicyDTO) GetElementId() string {
	if o == nil || isNil(o.ElementId) {
		var ret string
		return ret
	}
	return *o.ElementId
}

// GetElementIdOk returns a tuple with the ElementId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AuthenticationAssertionEmissionPolicyDTO) GetElementIdOk() (*string, bool) {
	if o == nil || isNil(o.ElementId) {
    return nil, false
	}
	return o.ElementId, true
}

// HasElementId returns a boolean if a field has been set.
func (o *AuthenticationAssertionEmissionPolicyDTO) HasElementId() bool {
	if o != nil && !isNil(o.ElementId) {
		return true
	}

	return false
}

// SetElementId gets a reference to the given string and assigns it to the ElementId field.
func (o *AuthenticationAssertionEmissionPolicyDTO) SetElementId(v string) {
	o.ElementId = &v
}

// GetId returns the Id field value if set, zero value otherwise.
func (o *AuthenticationAssertionEmissionPolicyDTO) GetId() int64 {
	if o == nil || isNil(o.Id) {
		var ret int64
		return ret
	}
	return *o.Id
}

// GetIdOk returns a tuple with the Id field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AuthenticationAssertionEmissionPolicyDTO) GetIdOk() (*int64, bool) {
	if o == nil || isNil(o.Id) {
    return nil, false
	}
	return o.Id, true
}

// HasId returns a boolean if a field has been set.
func (o *AuthenticationAssertionEmissionPolicyDTO) HasId() bool {
	if o != nil && !isNil(o.Id) {
		return true
	}

	return false
}

// SetId gets a reference to the given int64 and assigns it to the Id field.
func (o *AuthenticationAssertionEmissionPolicyDTO) SetId(v int64) {
	o.Id = &v
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *AuthenticationAssertionEmissionPolicyDTO) GetName() string {
	if o == nil || isNil(o.Name) {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AuthenticationAssertionEmissionPolicyDTO) GetNameOk() (*string, bool) {
	if o == nil || isNil(o.Name) {
    return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *AuthenticationAssertionEmissionPolicyDTO) HasName() bool {
	if o != nil && !isNil(o.Name) {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *AuthenticationAssertionEmissionPolicyDTO) SetName(v string) {
	o.Name = &v
}

func (o AuthenticationAssertionEmissionPolicyDTO) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if !isNil(o.ElementId) {
		toSerialize["elementId"] = o.ElementId
	}
	if !isNil(o.Id) {
		toSerialize["id"] = o.Id
	}
	if !isNil(o.Name) {
		toSerialize["name"] = o.Name
	}

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return json.Marshal(toSerialize)
}

func (o *AuthenticationAssertionEmissionPolicyDTO) UnmarshalJSON(bytes []byte) (err error) {
	varAuthenticationAssertionEmissionPolicyDTO := _AuthenticationAssertionEmissionPolicyDTO{}

	if err = json.Unmarshal(bytes, &varAuthenticationAssertionEmissionPolicyDTO); err == nil {
		*o = AuthenticationAssertionEmissionPolicyDTO(varAuthenticationAssertionEmissionPolicyDTO)
	}

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(bytes, &additionalProperties); err == nil {
		delete(additionalProperties, "elementId")
		delete(additionalProperties, "id")
		delete(additionalProperties, "name")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableAuthenticationAssertionEmissionPolicyDTO struct {
	value *AuthenticationAssertionEmissionPolicyDTO
	isSet bool
}

func (v NullableAuthenticationAssertionEmissionPolicyDTO) Get() *AuthenticationAssertionEmissionPolicyDTO {
	return v.value
}

func (v *NullableAuthenticationAssertionEmissionPolicyDTO) Set(val *AuthenticationAssertionEmissionPolicyDTO) {
	v.value = val
	v.isSet = true
}

func (v NullableAuthenticationAssertionEmissionPolicyDTO) IsSet() bool {
	return v.isSet
}

func (v *NullableAuthenticationAssertionEmissionPolicyDTO) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAuthenticationAssertionEmissionPolicyDTO(val *AuthenticationAssertionEmissionPolicyDTO) *NullableAuthenticationAssertionEmissionPolicyDTO {
	return &NullableAuthenticationAssertionEmissionPolicyDTO{value: val, isSet: true}
}

func (v NullableAuthenticationAssertionEmissionPolicyDTO) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAuthenticationAssertionEmissionPolicyDTO) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


