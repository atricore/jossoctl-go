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

// GetExtSaml2SpRes struct for GetExtSaml2SpRes
type GetExtSaml2SpRes struct {
	Config *SamlR2SPConfigDTO `json:"config,omitempty"`
	Error *string `json:"error,omitempty"`
	Sp *ExternalSaml2ServiceProviderDTO `json:"sp,omitempty"`
	ValidationErrors []string `json:"validationErrors,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _GetExtSaml2SpRes GetExtSaml2SpRes

// NewGetExtSaml2SpRes instantiates a new GetExtSaml2SpRes object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewGetExtSaml2SpRes() *GetExtSaml2SpRes {
	this := GetExtSaml2SpRes{}
	return &this
}

// NewGetExtSaml2SpResWithDefaults instantiates a new GetExtSaml2SpRes object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewGetExtSaml2SpResWithDefaults() *GetExtSaml2SpRes {
	this := GetExtSaml2SpRes{}
	return &this
}

// GetConfig returns the Config field value if set, zero value otherwise.
func (o *GetExtSaml2SpRes) GetConfig() SamlR2SPConfigDTO {
	if o == nil || isNil(o.Config) {
		var ret SamlR2SPConfigDTO
		return ret
	}
	return *o.Config
}

// GetConfigOk returns a tuple with the Config field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetExtSaml2SpRes) GetConfigOk() (*SamlR2SPConfigDTO, bool) {
	if o == nil || isNil(o.Config) {
    return nil, false
	}
	return o.Config, true
}

// HasConfig returns a boolean if a field has been set.
func (o *GetExtSaml2SpRes) HasConfig() bool {
	if o != nil && !isNil(o.Config) {
		return true
	}

	return false
}

// SetConfig gets a reference to the given SamlR2SPConfigDTO and assigns it to the Config field.
func (o *GetExtSaml2SpRes) SetConfig(v SamlR2SPConfigDTO) {
	o.Config = &v
}

// GetError returns the Error field value if set, zero value otherwise.
func (o *GetExtSaml2SpRes) GetError() string {
	if o == nil || isNil(o.Error) {
		var ret string
		return ret
	}
	return *o.Error
}

// GetErrorOk returns a tuple with the Error field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetExtSaml2SpRes) GetErrorOk() (*string, bool) {
	if o == nil || isNil(o.Error) {
    return nil, false
	}
	return o.Error, true
}

// HasError returns a boolean if a field has been set.
func (o *GetExtSaml2SpRes) HasError() bool {
	if o != nil && !isNil(o.Error) {
		return true
	}

	return false
}

// SetError gets a reference to the given string and assigns it to the Error field.
func (o *GetExtSaml2SpRes) SetError(v string) {
	o.Error = &v
}

// GetSp returns the Sp field value if set, zero value otherwise.
func (o *GetExtSaml2SpRes) GetSp() ExternalSaml2ServiceProviderDTO {
	if o == nil || isNil(o.Sp) {
		var ret ExternalSaml2ServiceProviderDTO
		return ret
	}
	return *o.Sp
}

// GetSpOk returns a tuple with the Sp field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetExtSaml2SpRes) GetSpOk() (*ExternalSaml2ServiceProviderDTO, bool) {
	if o == nil || isNil(o.Sp) {
    return nil, false
	}
	return o.Sp, true
}

// HasSp returns a boolean if a field has been set.
func (o *GetExtSaml2SpRes) HasSp() bool {
	if o != nil && !isNil(o.Sp) {
		return true
	}

	return false
}

// SetSp gets a reference to the given ExternalSaml2ServiceProviderDTO and assigns it to the Sp field.
func (o *GetExtSaml2SpRes) SetSp(v ExternalSaml2ServiceProviderDTO) {
	o.Sp = &v
}

// GetValidationErrors returns the ValidationErrors field value if set, zero value otherwise.
func (o *GetExtSaml2SpRes) GetValidationErrors() []string {
	if o == nil || isNil(o.ValidationErrors) {
		var ret []string
		return ret
	}
	return o.ValidationErrors
}

// GetValidationErrorsOk returns a tuple with the ValidationErrors field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetExtSaml2SpRes) GetValidationErrorsOk() ([]string, bool) {
	if o == nil || isNil(o.ValidationErrors) {
    return nil, false
	}
	return o.ValidationErrors, true
}

// HasValidationErrors returns a boolean if a field has been set.
func (o *GetExtSaml2SpRes) HasValidationErrors() bool {
	if o != nil && !isNil(o.ValidationErrors) {
		return true
	}

	return false
}

// SetValidationErrors gets a reference to the given []string and assigns it to the ValidationErrors field.
func (o *GetExtSaml2SpRes) SetValidationErrors(v []string) {
	o.ValidationErrors = v
}

func (o GetExtSaml2SpRes) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if !isNil(o.Config) {
		toSerialize["config"] = o.Config
	}
	if !isNil(o.Error) {
		toSerialize["error"] = o.Error
	}
	if !isNil(o.Sp) {
		toSerialize["sp"] = o.Sp
	}
	if !isNil(o.ValidationErrors) {
		toSerialize["validationErrors"] = o.ValidationErrors
	}

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return json.Marshal(toSerialize)
}

func (o *GetExtSaml2SpRes) UnmarshalJSON(bytes []byte) (err error) {
	varGetExtSaml2SpRes := _GetExtSaml2SpRes{}

	if err = json.Unmarshal(bytes, &varGetExtSaml2SpRes); err == nil {
		*o = GetExtSaml2SpRes(varGetExtSaml2SpRes)
	}

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(bytes, &additionalProperties); err == nil {
		delete(additionalProperties, "config")
		delete(additionalProperties, "error")
		delete(additionalProperties, "sp")
		delete(additionalProperties, "validationErrors")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableGetExtSaml2SpRes struct {
	value *GetExtSaml2SpRes
	isSet bool
}

func (v NullableGetExtSaml2SpRes) Get() *GetExtSaml2SpRes {
	return v.value
}

func (v *NullableGetExtSaml2SpRes) Set(val *GetExtSaml2SpRes) {
	v.value = val
	v.isSet = true
}

func (v NullableGetExtSaml2SpRes) IsSet() bool {
	return v.isSet
}

func (v *NullableGetExtSaml2SpRes) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableGetExtSaml2SpRes(val *GetExtSaml2SpRes) *NullableGetExtSaml2SpRes {
	return &NullableGetExtSaml2SpRes{value: val, isSet: true}
}

func (v NullableGetExtSaml2SpRes) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableGetExtSaml2SpRes) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


