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

// GetIdSourcesReq struct for GetIdSourcesReq
type GetIdSourcesReq struct {
	IdOrName *string `json:"idOrName,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _GetIdSourcesReq GetIdSourcesReq

// NewGetIdSourcesReq instantiates a new GetIdSourcesReq object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewGetIdSourcesReq() *GetIdSourcesReq {
	this := GetIdSourcesReq{}
	return &this
}

// NewGetIdSourcesReqWithDefaults instantiates a new GetIdSourcesReq object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewGetIdSourcesReqWithDefaults() *GetIdSourcesReq {
	this := GetIdSourcesReq{}
	return &this
}

// GetIdOrName returns the IdOrName field value if set, zero value otherwise.
func (o *GetIdSourcesReq) GetIdOrName() string {
	if o == nil || isNil(o.IdOrName) {
		var ret string
		return ret
	}
	return *o.IdOrName
}

// GetIdOrNameOk returns a tuple with the IdOrName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetIdSourcesReq) GetIdOrNameOk() (*string, bool) {
	if o == nil || isNil(o.IdOrName) {
    return nil, false
	}
	return o.IdOrName, true
}

// HasIdOrName returns a boolean if a field has been set.
func (o *GetIdSourcesReq) HasIdOrName() bool {
	if o != nil && !isNil(o.IdOrName) {
		return true
	}

	return false
}

// SetIdOrName gets a reference to the given string and assigns it to the IdOrName field.
func (o *GetIdSourcesReq) SetIdOrName(v string) {
	o.IdOrName = &v
}

func (o GetIdSourcesReq) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if !isNil(o.IdOrName) {
		toSerialize["idOrName"] = o.IdOrName
	}

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return json.Marshal(toSerialize)
}

func (o *GetIdSourcesReq) UnmarshalJSON(bytes []byte) (err error) {
	varGetIdSourcesReq := _GetIdSourcesReq{}

	if err = json.Unmarshal(bytes, &varGetIdSourcesReq); err == nil {
		*o = GetIdSourcesReq(varGetIdSourcesReq)
	}

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(bytes, &additionalProperties); err == nil {
		delete(additionalProperties, "idOrName")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableGetIdSourcesReq struct {
	value *GetIdSourcesReq
	isSet bool
}

func (v NullableGetIdSourcesReq) Get() *GetIdSourcesReq {
	return v.value
}

func (v *NullableGetIdSourcesReq) Set(val *GetIdSourcesReq) {
	v.value = val
	v.isSet = true
}

func (v NullableGetIdSourcesReq) IsSet() bool {
	return v.isSet
}

func (v *NullableGetIdSourcesReq) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableGetIdSourcesReq(val *GetIdSourcesReq) *NullableGetIdSourcesReq {
	return &NullableGetIdSourcesReq{value: val, isSet: true}
}

func (v NullableGetIdSourcesReq) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableGetIdSourcesReq) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

