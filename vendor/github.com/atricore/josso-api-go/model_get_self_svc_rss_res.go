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

// GetSelfSvcRssRes struct for GetSelfSvcRssRes
type GetSelfSvcRssRes struct {
	Error *string `json:"error,omitempty"`
	Resources []SelfServicesResourceDTO `json:"resources,omitempty"`
	ValidationErrors []string `json:"validationErrors,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _GetSelfSvcRssRes GetSelfSvcRssRes

// NewGetSelfSvcRssRes instantiates a new GetSelfSvcRssRes object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewGetSelfSvcRssRes() *GetSelfSvcRssRes {
	this := GetSelfSvcRssRes{}
	return &this
}

// NewGetSelfSvcRssResWithDefaults instantiates a new GetSelfSvcRssRes object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewGetSelfSvcRssResWithDefaults() *GetSelfSvcRssRes {
	this := GetSelfSvcRssRes{}
	return &this
}

// GetError returns the Error field value if set, zero value otherwise.
func (o *GetSelfSvcRssRes) GetError() string {
	if o == nil || isNil(o.Error) {
		var ret string
		return ret
	}
	return *o.Error
}

// GetErrorOk returns a tuple with the Error field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetSelfSvcRssRes) GetErrorOk() (*string, bool) {
	if o == nil || isNil(o.Error) {
    return nil, false
	}
	return o.Error, true
}

// HasError returns a boolean if a field has been set.
func (o *GetSelfSvcRssRes) HasError() bool {
	if o != nil && !isNil(o.Error) {
		return true
	}

	return false
}

// SetError gets a reference to the given string and assigns it to the Error field.
func (o *GetSelfSvcRssRes) SetError(v string) {
	o.Error = &v
}

// GetResources returns the Resources field value if set, zero value otherwise.
func (o *GetSelfSvcRssRes) GetResources() []SelfServicesResourceDTO {
	if o == nil || isNil(o.Resources) {
		var ret []SelfServicesResourceDTO
		return ret
	}
	return o.Resources
}

// GetResourcesOk returns a tuple with the Resources field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetSelfSvcRssRes) GetResourcesOk() ([]SelfServicesResourceDTO, bool) {
	if o == nil || isNil(o.Resources) {
    return nil, false
	}
	return o.Resources, true
}

// HasResources returns a boolean if a field has been set.
func (o *GetSelfSvcRssRes) HasResources() bool {
	if o != nil && !isNil(o.Resources) {
		return true
	}

	return false
}

// SetResources gets a reference to the given []SelfServicesResourceDTO and assigns it to the Resources field.
func (o *GetSelfSvcRssRes) SetResources(v []SelfServicesResourceDTO) {
	o.Resources = v
}

// GetValidationErrors returns the ValidationErrors field value if set, zero value otherwise.
func (o *GetSelfSvcRssRes) GetValidationErrors() []string {
	if o == nil || isNil(o.ValidationErrors) {
		var ret []string
		return ret
	}
	return o.ValidationErrors
}

// GetValidationErrorsOk returns a tuple with the ValidationErrors field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetSelfSvcRssRes) GetValidationErrorsOk() ([]string, bool) {
	if o == nil || isNil(o.ValidationErrors) {
    return nil, false
	}
	return o.ValidationErrors, true
}

// HasValidationErrors returns a boolean if a field has been set.
func (o *GetSelfSvcRssRes) HasValidationErrors() bool {
	if o != nil && !isNil(o.ValidationErrors) {
		return true
	}

	return false
}

// SetValidationErrors gets a reference to the given []string and assigns it to the ValidationErrors field.
func (o *GetSelfSvcRssRes) SetValidationErrors(v []string) {
	o.ValidationErrors = v
}

func (o GetSelfSvcRssRes) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if !isNil(o.Error) {
		toSerialize["error"] = o.Error
	}
	if !isNil(o.Resources) {
		toSerialize["resources"] = o.Resources
	}
	if !isNil(o.ValidationErrors) {
		toSerialize["validationErrors"] = o.ValidationErrors
	}

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return json.Marshal(toSerialize)
}

func (o *GetSelfSvcRssRes) UnmarshalJSON(bytes []byte) (err error) {
	varGetSelfSvcRssRes := _GetSelfSvcRssRes{}

	if err = json.Unmarshal(bytes, &varGetSelfSvcRssRes); err == nil {
		*o = GetSelfSvcRssRes(varGetSelfSvcRssRes)
	}

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(bytes, &additionalProperties); err == nil {
		delete(additionalProperties, "error")
		delete(additionalProperties, "resources")
		delete(additionalProperties, "validationErrors")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableGetSelfSvcRssRes struct {
	value *GetSelfSvcRssRes
	isSet bool
}

func (v NullableGetSelfSvcRssRes) Get() *GetSelfSvcRssRes {
	return v.value
}

func (v *NullableGetSelfSvcRssRes) Set(val *GetSelfSvcRssRes) {
	v.value = val
	v.isSet = true
}

func (v NullableGetSelfSvcRssRes) IsSet() bool {
	return v.isSet
}

func (v *NullableGetSelfSvcRssRes) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableGetSelfSvcRssRes(val *GetSelfSvcRssRes) *NullableGetSelfSvcRssRes {
	return &NullableGetSelfSvcRssRes{value: val, isSet: true}
}

func (v NullableGetSelfSvcRssRes) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableGetSelfSvcRssRes) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


