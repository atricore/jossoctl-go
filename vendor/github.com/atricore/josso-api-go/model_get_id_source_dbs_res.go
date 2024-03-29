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

// GetIdSourceDbsRes struct for GetIdSourceDbsRes
type GetIdSourceDbsRes struct {
	Error *string `json:"error,omitempty"`
	IdSourceDbs []DbIdentitySourceDTO `json:"idSourceDbs,omitempty"`
	ValidationErrors []string `json:"validationErrors,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _GetIdSourceDbsRes GetIdSourceDbsRes

// NewGetIdSourceDbsRes instantiates a new GetIdSourceDbsRes object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewGetIdSourceDbsRes() *GetIdSourceDbsRes {
	this := GetIdSourceDbsRes{}
	return &this
}

// NewGetIdSourceDbsResWithDefaults instantiates a new GetIdSourceDbsRes object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewGetIdSourceDbsResWithDefaults() *GetIdSourceDbsRes {
	this := GetIdSourceDbsRes{}
	return &this
}

// GetError returns the Error field value if set, zero value otherwise.
func (o *GetIdSourceDbsRes) GetError() string {
	if o == nil || isNil(o.Error) {
		var ret string
		return ret
	}
	return *o.Error
}

// GetErrorOk returns a tuple with the Error field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetIdSourceDbsRes) GetErrorOk() (*string, bool) {
	if o == nil || isNil(o.Error) {
    return nil, false
	}
	return o.Error, true
}

// HasError returns a boolean if a field has been set.
func (o *GetIdSourceDbsRes) HasError() bool {
	if o != nil && !isNil(o.Error) {
		return true
	}

	return false
}

// SetError gets a reference to the given string and assigns it to the Error field.
func (o *GetIdSourceDbsRes) SetError(v string) {
	o.Error = &v
}

// GetIdSourceDbs returns the IdSourceDbs field value if set, zero value otherwise.
func (o *GetIdSourceDbsRes) GetIdSourceDbs() []DbIdentitySourceDTO {
	if o == nil || isNil(o.IdSourceDbs) {
		var ret []DbIdentitySourceDTO
		return ret
	}
	return o.IdSourceDbs
}

// GetIdSourceDbsOk returns a tuple with the IdSourceDbs field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetIdSourceDbsRes) GetIdSourceDbsOk() ([]DbIdentitySourceDTO, bool) {
	if o == nil || isNil(o.IdSourceDbs) {
    return nil, false
	}
	return o.IdSourceDbs, true
}

// HasIdSourceDbs returns a boolean if a field has been set.
func (o *GetIdSourceDbsRes) HasIdSourceDbs() bool {
	if o != nil && !isNil(o.IdSourceDbs) {
		return true
	}

	return false
}

// SetIdSourceDbs gets a reference to the given []DbIdentitySourceDTO and assigns it to the IdSourceDbs field.
func (o *GetIdSourceDbsRes) SetIdSourceDbs(v []DbIdentitySourceDTO) {
	o.IdSourceDbs = v
}

// GetValidationErrors returns the ValidationErrors field value if set, zero value otherwise.
func (o *GetIdSourceDbsRes) GetValidationErrors() []string {
	if o == nil || isNil(o.ValidationErrors) {
		var ret []string
		return ret
	}
	return o.ValidationErrors
}

// GetValidationErrorsOk returns a tuple with the ValidationErrors field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetIdSourceDbsRes) GetValidationErrorsOk() ([]string, bool) {
	if o == nil || isNil(o.ValidationErrors) {
    return nil, false
	}
	return o.ValidationErrors, true
}

// HasValidationErrors returns a boolean if a field has been set.
func (o *GetIdSourceDbsRes) HasValidationErrors() bool {
	if o != nil && !isNil(o.ValidationErrors) {
		return true
	}

	return false
}

// SetValidationErrors gets a reference to the given []string and assigns it to the ValidationErrors field.
func (o *GetIdSourceDbsRes) SetValidationErrors(v []string) {
	o.ValidationErrors = v
}

func (o GetIdSourceDbsRes) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if !isNil(o.Error) {
		toSerialize["error"] = o.Error
	}
	if !isNil(o.IdSourceDbs) {
		toSerialize["idSourceDbs"] = o.IdSourceDbs
	}
	if !isNil(o.ValidationErrors) {
		toSerialize["validationErrors"] = o.ValidationErrors
	}

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return json.Marshal(toSerialize)
}

func (o *GetIdSourceDbsRes) UnmarshalJSON(bytes []byte) (err error) {
	varGetIdSourceDbsRes := _GetIdSourceDbsRes{}

	if err = json.Unmarshal(bytes, &varGetIdSourceDbsRes); err == nil {
		*o = GetIdSourceDbsRes(varGetIdSourceDbsRes)
	}

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(bytes, &additionalProperties); err == nil {
		delete(additionalProperties, "error")
		delete(additionalProperties, "idSourceDbs")
		delete(additionalProperties, "validationErrors")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableGetIdSourceDbsRes struct {
	value *GetIdSourceDbsRes
	isSet bool
}

func (v NullableGetIdSourceDbsRes) Get() *GetIdSourceDbsRes {
	return v.value
}

func (v *NullableGetIdSourceDbsRes) Set(val *GetIdSourceDbsRes) {
	v.value = val
	v.isSet = true
}

func (v NullableGetIdSourceDbsRes) IsSet() bool {
	return v.isSet
}

func (v *NullableGetIdSourceDbsRes) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableGetIdSourceDbsRes(val *GetIdSourceDbsRes) *NullableGetIdSourceDbsRes {
	return &NullableGetIdSourceDbsRes{value: val, isSet: true}
}

func (v NullableGetIdSourceDbsRes) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableGetIdSourceDbsRes) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


