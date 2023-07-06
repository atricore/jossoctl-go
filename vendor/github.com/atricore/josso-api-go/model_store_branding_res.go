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

// StoreBrandingRes struct for StoreBrandingRes
type StoreBrandingRes struct {
	Branding *CustomBrandingDefinitionDTO `json:"branding,omitempty"`
	Error *string `json:"error,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _StoreBrandingRes StoreBrandingRes

// NewStoreBrandingRes instantiates a new StoreBrandingRes object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewStoreBrandingRes() *StoreBrandingRes {
	this := StoreBrandingRes{}
	return &this
}

// NewStoreBrandingResWithDefaults instantiates a new StoreBrandingRes object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewStoreBrandingResWithDefaults() *StoreBrandingRes {
	this := StoreBrandingRes{}
	return &this
}

// GetBranding returns the Branding field value if set, zero value otherwise.
func (o *StoreBrandingRes) GetBranding() CustomBrandingDefinitionDTO {
	if o == nil || isNil(o.Branding) {
		var ret CustomBrandingDefinitionDTO
		return ret
	}
	return *o.Branding
}

// GetBrandingOk returns a tuple with the Branding field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StoreBrandingRes) GetBrandingOk() (*CustomBrandingDefinitionDTO, bool) {
	if o == nil || isNil(o.Branding) {
    return nil, false
	}
	return o.Branding, true
}

// HasBranding returns a boolean if a field has been set.
func (o *StoreBrandingRes) HasBranding() bool {
	if o != nil && !isNil(o.Branding) {
		return true
	}

	return false
}

// SetBranding gets a reference to the given CustomBrandingDefinitionDTO and assigns it to the Branding field.
func (o *StoreBrandingRes) SetBranding(v CustomBrandingDefinitionDTO) {
	o.Branding = &v
}

// GetError returns the Error field value if set, zero value otherwise.
func (o *StoreBrandingRes) GetError() string {
	if o == nil || isNil(o.Error) {
		var ret string
		return ret
	}
	return *o.Error
}

// GetErrorOk returns a tuple with the Error field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StoreBrandingRes) GetErrorOk() (*string, bool) {
	if o == nil || isNil(o.Error) {
    return nil, false
	}
	return o.Error, true
}

// HasError returns a boolean if a field has been set.
func (o *StoreBrandingRes) HasError() bool {
	if o != nil && !isNil(o.Error) {
		return true
	}

	return false
}

// SetError gets a reference to the given string and assigns it to the Error field.
func (o *StoreBrandingRes) SetError(v string) {
	o.Error = &v
}

func (o StoreBrandingRes) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if !isNil(o.Branding) {
		toSerialize["branding"] = o.Branding
	}
	if !isNil(o.Error) {
		toSerialize["error"] = o.Error
	}

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return json.Marshal(toSerialize)
}

func (o *StoreBrandingRes) UnmarshalJSON(bytes []byte) (err error) {
	varStoreBrandingRes := _StoreBrandingRes{}

	if err = json.Unmarshal(bytes, &varStoreBrandingRes); err == nil {
		*o = StoreBrandingRes(varStoreBrandingRes)
	}

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(bytes, &additionalProperties); err == nil {
		delete(additionalProperties, "branding")
		delete(additionalProperties, "error")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableStoreBrandingRes struct {
	value *StoreBrandingRes
	isSet bool
}

func (v NullableStoreBrandingRes) Get() *StoreBrandingRes {
	return v.value
}

func (v *NullableStoreBrandingRes) Set(val *StoreBrandingRes) {
	v.value = val
	v.isSet = true
}

func (v NullableStoreBrandingRes) IsSet() bool {
	return v.isSet
}

func (v *NullableStoreBrandingRes) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableStoreBrandingRes(val *StoreBrandingRes) *NullableStoreBrandingRes {
	return &NullableStoreBrandingRes{value: val, isSet: true}
}

func (v NullableStoreBrandingRes) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableStoreBrandingRes) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


