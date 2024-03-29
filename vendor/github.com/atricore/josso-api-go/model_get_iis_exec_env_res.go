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

// GetIisExecEnvRes struct for GetIisExecEnvRes
type GetIisExecEnvRes struct {
	Error *string `json:"error,omitempty"`
	IisExecEnv *WindowsIISExecutionEnvironmentDTO `json:"iisExecEnv,omitempty"`
	ValidationErrors []string `json:"validationErrors,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _GetIisExecEnvRes GetIisExecEnvRes

// NewGetIisExecEnvRes instantiates a new GetIisExecEnvRes object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewGetIisExecEnvRes() *GetIisExecEnvRes {
	this := GetIisExecEnvRes{}
	return &this
}

// NewGetIisExecEnvResWithDefaults instantiates a new GetIisExecEnvRes object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewGetIisExecEnvResWithDefaults() *GetIisExecEnvRes {
	this := GetIisExecEnvRes{}
	return &this
}

// GetError returns the Error field value if set, zero value otherwise.
func (o *GetIisExecEnvRes) GetError() string {
	if o == nil || isNil(o.Error) {
		var ret string
		return ret
	}
	return *o.Error
}

// GetErrorOk returns a tuple with the Error field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetIisExecEnvRes) GetErrorOk() (*string, bool) {
	if o == nil || isNil(o.Error) {
    return nil, false
	}
	return o.Error, true
}

// HasError returns a boolean if a field has been set.
func (o *GetIisExecEnvRes) HasError() bool {
	if o != nil && !isNil(o.Error) {
		return true
	}

	return false
}

// SetError gets a reference to the given string and assigns it to the Error field.
func (o *GetIisExecEnvRes) SetError(v string) {
	o.Error = &v
}

// GetIisExecEnv returns the IisExecEnv field value if set, zero value otherwise.
func (o *GetIisExecEnvRes) GetIisExecEnv() WindowsIISExecutionEnvironmentDTO {
	if o == nil || isNil(o.IisExecEnv) {
		var ret WindowsIISExecutionEnvironmentDTO
		return ret
	}
	return *o.IisExecEnv
}

// GetIisExecEnvOk returns a tuple with the IisExecEnv field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetIisExecEnvRes) GetIisExecEnvOk() (*WindowsIISExecutionEnvironmentDTO, bool) {
	if o == nil || isNil(o.IisExecEnv) {
    return nil, false
	}
	return o.IisExecEnv, true
}

// HasIisExecEnv returns a boolean if a field has been set.
func (o *GetIisExecEnvRes) HasIisExecEnv() bool {
	if o != nil && !isNil(o.IisExecEnv) {
		return true
	}

	return false
}

// SetIisExecEnv gets a reference to the given WindowsIISExecutionEnvironmentDTO and assigns it to the IisExecEnv field.
func (o *GetIisExecEnvRes) SetIisExecEnv(v WindowsIISExecutionEnvironmentDTO) {
	o.IisExecEnv = &v
}

// GetValidationErrors returns the ValidationErrors field value if set, zero value otherwise.
func (o *GetIisExecEnvRes) GetValidationErrors() []string {
	if o == nil || isNil(o.ValidationErrors) {
		var ret []string
		return ret
	}
	return o.ValidationErrors
}

// GetValidationErrorsOk returns a tuple with the ValidationErrors field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetIisExecEnvRes) GetValidationErrorsOk() ([]string, bool) {
	if o == nil || isNil(o.ValidationErrors) {
    return nil, false
	}
	return o.ValidationErrors, true
}

// HasValidationErrors returns a boolean if a field has been set.
func (o *GetIisExecEnvRes) HasValidationErrors() bool {
	if o != nil && !isNil(o.ValidationErrors) {
		return true
	}

	return false
}

// SetValidationErrors gets a reference to the given []string and assigns it to the ValidationErrors field.
func (o *GetIisExecEnvRes) SetValidationErrors(v []string) {
	o.ValidationErrors = v
}

func (o GetIisExecEnvRes) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if !isNil(o.Error) {
		toSerialize["error"] = o.Error
	}
	if !isNil(o.IisExecEnv) {
		toSerialize["iisExecEnv"] = o.IisExecEnv
	}
	if !isNil(o.ValidationErrors) {
		toSerialize["validationErrors"] = o.ValidationErrors
	}

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return json.Marshal(toSerialize)
}

func (o *GetIisExecEnvRes) UnmarshalJSON(bytes []byte) (err error) {
	varGetIisExecEnvRes := _GetIisExecEnvRes{}

	if err = json.Unmarshal(bytes, &varGetIisExecEnvRes); err == nil {
		*o = GetIisExecEnvRes(varGetIisExecEnvRes)
	}

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(bytes, &additionalProperties); err == nil {
		delete(additionalProperties, "error")
		delete(additionalProperties, "iisExecEnv")
		delete(additionalProperties, "validationErrors")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableGetIisExecEnvRes struct {
	value *GetIisExecEnvRes
	isSet bool
}

func (v NullableGetIisExecEnvRes) Get() *GetIisExecEnvRes {
	return v.value
}

func (v *NullableGetIisExecEnvRes) Set(val *GetIisExecEnvRes) {
	v.value = val
	v.isSet = true
}

func (v NullableGetIisExecEnvRes) IsSet() bool {
	return v.isSet
}

func (v *NullableGetIisExecEnvRes) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableGetIisExecEnvRes(val *GetIisExecEnvRes) *NullableGetIisExecEnvRes {
	return &NullableGetIisExecEnvRes{value: val, isSet: true}
}

func (v NullableGetIisExecEnvRes) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableGetIisExecEnvRes) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


