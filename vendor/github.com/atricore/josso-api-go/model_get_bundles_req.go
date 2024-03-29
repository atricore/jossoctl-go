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

// GetBundlesReq struct for GetBundlesReq
type GetBundlesReq struct {
	IdOrName *string `json:"idOrName,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _GetBundlesReq GetBundlesReq

// NewGetBundlesReq instantiates a new GetBundlesReq object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewGetBundlesReq() *GetBundlesReq {
	this := GetBundlesReq{}
	return &this
}

// NewGetBundlesReqWithDefaults instantiates a new GetBundlesReq object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewGetBundlesReqWithDefaults() *GetBundlesReq {
	this := GetBundlesReq{}
	return &this
}

// GetIdOrName returns the IdOrName field value if set, zero value otherwise.
func (o *GetBundlesReq) GetIdOrName() string {
	if o == nil || isNil(o.IdOrName) {
		var ret string
		return ret
	}
	return *o.IdOrName
}

// GetIdOrNameOk returns a tuple with the IdOrName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetBundlesReq) GetIdOrNameOk() (*string, bool) {
	if o == nil || isNil(o.IdOrName) {
    return nil, false
	}
	return o.IdOrName, true
}

// HasIdOrName returns a boolean if a field has been set.
func (o *GetBundlesReq) HasIdOrName() bool {
	if o != nil && !isNil(o.IdOrName) {
		return true
	}

	return false
}

// SetIdOrName gets a reference to the given string and assigns it to the IdOrName field.
func (o *GetBundlesReq) SetIdOrName(v string) {
	o.IdOrName = &v
}

func (o GetBundlesReq) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if !isNil(o.IdOrName) {
		toSerialize["idOrName"] = o.IdOrName
	}

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return json.Marshal(toSerialize)
}

func (o *GetBundlesReq) UnmarshalJSON(bytes []byte) (err error) {
	varGetBundlesReq := _GetBundlesReq{}

	if err = json.Unmarshal(bytes, &varGetBundlesReq); err == nil {
		*o = GetBundlesReq(varGetBundlesReq)
	}

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(bytes, &additionalProperties); err == nil {
		delete(additionalProperties, "idOrName")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableGetBundlesReq struct {
	value *GetBundlesReq
	isSet bool
}

func (v NullableGetBundlesReq) Get() *GetBundlesReq {
	return v.value
}

func (v *NullableGetBundlesReq) Set(val *GetBundlesReq) {
	v.value = val
	v.isSet = true
}

func (v NullableGetBundlesReq) IsSet() bool {
	return v.isSet
}

func (v *NullableGetBundlesReq) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableGetBundlesReq(val *GetBundlesReq) *NullableGetBundlesReq {
	return &NullableGetBundlesReq{value: val, isSet: true}
}

func (v NullableGetBundlesReq) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableGetBundlesReq) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


