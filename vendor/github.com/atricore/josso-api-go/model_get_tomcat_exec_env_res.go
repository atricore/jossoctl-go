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

// GetTomcatExecEnvRes struct for GetTomcatExecEnvRes
type GetTomcatExecEnvRes struct {
	Error *string `json:"error,omitempty"`
	TomcatExecEnv *TomcatExecutionEnvironmentDTO `json:"tomcatExecEnv,omitempty"`
	ValidationErrors []string `json:"validationErrors,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _GetTomcatExecEnvRes GetTomcatExecEnvRes

// NewGetTomcatExecEnvRes instantiates a new GetTomcatExecEnvRes object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewGetTomcatExecEnvRes() *GetTomcatExecEnvRes {
	this := GetTomcatExecEnvRes{}
	return &this
}

// NewGetTomcatExecEnvResWithDefaults instantiates a new GetTomcatExecEnvRes object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewGetTomcatExecEnvResWithDefaults() *GetTomcatExecEnvRes {
	this := GetTomcatExecEnvRes{}
	return &this
}

// GetError returns the Error field value if set, zero value otherwise.
func (o *GetTomcatExecEnvRes) GetError() string {
	if o == nil || isNil(o.Error) {
		var ret string
		return ret
	}
	return *o.Error
}

// GetErrorOk returns a tuple with the Error field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetTomcatExecEnvRes) GetErrorOk() (*string, bool) {
	if o == nil || isNil(o.Error) {
    return nil, false
	}
	return o.Error, true
}

// HasError returns a boolean if a field has been set.
func (o *GetTomcatExecEnvRes) HasError() bool {
	if o != nil && !isNil(o.Error) {
		return true
	}

	return false
}

// SetError gets a reference to the given string and assigns it to the Error field.
func (o *GetTomcatExecEnvRes) SetError(v string) {
	o.Error = &v
}

// GetTomcatExecEnv returns the TomcatExecEnv field value if set, zero value otherwise.
func (o *GetTomcatExecEnvRes) GetTomcatExecEnv() TomcatExecutionEnvironmentDTO {
	if o == nil || isNil(o.TomcatExecEnv) {
		var ret TomcatExecutionEnvironmentDTO
		return ret
	}
	return *o.TomcatExecEnv
}

// GetTomcatExecEnvOk returns a tuple with the TomcatExecEnv field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetTomcatExecEnvRes) GetTomcatExecEnvOk() (*TomcatExecutionEnvironmentDTO, bool) {
	if o == nil || isNil(o.TomcatExecEnv) {
    return nil, false
	}
	return o.TomcatExecEnv, true
}

// HasTomcatExecEnv returns a boolean if a field has been set.
func (o *GetTomcatExecEnvRes) HasTomcatExecEnv() bool {
	if o != nil && !isNil(o.TomcatExecEnv) {
		return true
	}

	return false
}

// SetTomcatExecEnv gets a reference to the given TomcatExecutionEnvironmentDTO and assigns it to the TomcatExecEnv field.
func (o *GetTomcatExecEnvRes) SetTomcatExecEnv(v TomcatExecutionEnvironmentDTO) {
	o.TomcatExecEnv = &v
}

// GetValidationErrors returns the ValidationErrors field value if set, zero value otherwise.
func (o *GetTomcatExecEnvRes) GetValidationErrors() []string {
	if o == nil || isNil(o.ValidationErrors) {
		var ret []string
		return ret
	}
	return o.ValidationErrors
}

// GetValidationErrorsOk returns a tuple with the ValidationErrors field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetTomcatExecEnvRes) GetValidationErrorsOk() ([]string, bool) {
	if o == nil || isNil(o.ValidationErrors) {
    return nil, false
	}
	return o.ValidationErrors, true
}

// HasValidationErrors returns a boolean if a field has been set.
func (o *GetTomcatExecEnvRes) HasValidationErrors() bool {
	if o != nil && !isNil(o.ValidationErrors) {
		return true
	}

	return false
}

// SetValidationErrors gets a reference to the given []string and assigns it to the ValidationErrors field.
func (o *GetTomcatExecEnvRes) SetValidationErrors(v []string) {
	o.ValidationErrors = v
}

func (o GetTomcatExecEnvRes) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if !isNil(o.Error) {
		toSerialize["error"] = o.Error
	}
	if !isNil(o.TomcatExecEnv) {
		toSerialize["tomcatExecEnv"] = o.TomcatExecEnv
	}
	if !isNil(o.ValidationErrors) {
		toSerialize["validationErrors"] = o.ValidationErrors
	}

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return json.Marshal(toSerialize)
}

func (o *GetTomcatExecEnvRes) UnmarshalJSON(bytes []byte) (err error) {
	varGetTomcatExecEnvRes := _GetTomcatExecEnvRes{}

	if err = json.Unmarshal(bytes, &varGetTomcatExecEnvRes); err == nil {
		*o = GetTomcatExecEnvRes(varGetTomcatExecEnvRes)
	}

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(bytes, &additionalProperties); err == nil {
		delete(additionalProperties, "error")
		delete(additionalProperties, "tomcatExecEnv")
		delete(additionalProperties, "validationErrors")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableGetTomcatExecEnvRes struct {
	value *GetTomcatExecEnvRes
	isSet bool
}

func (v NullableGetTomcatExecEnvRes) Get() *GetTomcatExecEnvRes {
	return v.value
}

func (v *NullableGetTomcatExecEnvRes) Set(val *GetTomcatExecEnvRes) {
	v.value = val
	v.isSet = true
}

func (v NullableGetTomcatExecEnvRes) IsSet() bool {
	return v.isSet
}

func (v *NullableGetTomcatExecEnvRes) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableGetTomcatExecEnvRes(val *GetTomcatExecEnvRes) *NullableGetTomcatExecEnvRes {
	return &NullableGetTomcatExecEnvRes{value: val, isSet: true}
}

func (v NullableGetTomcatExecEnvRes) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableGetTomcatExecEnvRes) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


