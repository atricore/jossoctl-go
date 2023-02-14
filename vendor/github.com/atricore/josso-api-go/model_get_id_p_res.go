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

// GetIdPRes struct for GetIdPRes
type GetIdPRes struct {
	Config *SamlR2IDPConfigDTO `json:"config,omitempty"`
	Error *string `json:"error,omitempty"`
	Idp *IdentityProviderDTO `json:"idp,omitempty"`
	ValidationErrors []string `json:"validationErrors,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _GetIdPRes GetIdPRes

// NewGetIdPRes instantiates a new GetIdPRes object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewGetIdPRes() *GetIdPRes {
	this := GetIdPRes{}
	return &this
}

// NewGetIdPResWithDefaults instantiates a new GetIdPRes object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewGetIdPResWithDefaults() *GetIdPRes {
	this := GetIdPRes{}
	return &this
}

// GetConfig returns the Config field value if set, zero value otherwise.
func (o *GetIdPRes) GetConfig() SamlR2IDPConfigDTO {
	if o == nil || isNil(o.Config) {
		var ret SamlR2IDPConfigDTO
		return ret
	}
	return *o.Config
}

// GetConfigOk returns a tuple with the Config field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetIdPRes) GetConfigOk() (*SamlR2IDPConfigDTO, bool) {
	if o == nil || isNil(o.Config) {
    return nil, false
	}
	return o.Config, true
}

// HasConfig returns a boolean if a field has been set.
func (o *GetIdPRes) HasConfig() bool {
	if o != nil && !isNil(o.Config) {
		return true
	}

	return false
}

// SetConfig gets a reference to the given SamlR2IDPConfigDTO and assigns it to the Config field.
func (o *GetIdPRes) SetConfig(v SamlR2IDPConfigDTO) {
	o.Config = &v
}

// GetError returns the Error field value if set, zero value otherwise.
func (o *GetIdPRes) GetError() string {
	if o == nil || isNil(o.Error) {
		var ret string
		return ret
	}
	return *o.Error
}

// GetErrorOk returns a tuple with the Error field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetIdPRes) GetErrorOk() (*string, bool) {
	if o == nil || isNil(o.Error) {
    return nil, false
	}
	return o.Error, true
}

// HasError returns a boolean if a field has been set.
func (o *GetIdPRes) HasError() bool {
	if o != nil && !isNil(o.Error) {
		return true
	}

	return false
}

// SetError gets a reference to the given string and assigns it to the Error field.
func (o *GetIdPRes) SetError(v string) {
	o.Error = &v
}

// GetIdp returns the Idp field value if set, zero value otherwise.
func (o *GetIdPRes) GetIdp() IdentityProviderDTO {
	if o == nil || isNil(o.Idp) {
		var ret IdentityProviderDTO
		return ret
	}
	return *o.Idp
}

// GetIdpOk returns a tuple with the Idp field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetIdPRes) GetIdpOk() (*IdentityProviderDTO, bool) {
	if o == nil || isNil(o.Idp) {
    return nil, false
	}
	return o.Idp, true
}

// HasIdp returns a boolean if a field has been set.
func (o *GetIdPRes) HasIdp() bool {
	if o != nil && !isNil(o.Idp) {
		return true
	}

	return false
}

// SetIdp gets a reference to the given IdentityProviderDTO and assigns it to the Idp field.
func (o *GetIdPRes) SetIdp(v IdentityProviderDTO) {
	o.Idp = &v
}

// GetValidationErrors returns the ValidationErrors field value if set, zero value otherwise.
func (o *GetIdPRes) GetValidationErrors() []string {
	if o == nil || isNil(o.ValidationErrors) {
		var ret []string
		return ret
	}
	return o.ValidationErrors
}

// GetValidationErrorsOk returns a tuple with the ValidationErrors field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetIdPRes) GetValidationErrorsOk() ([]string, bool) {
	if o == nil || isNil(o.ValidationErrors) {
    return nil, false
	}
	return o.ValidationErrors, true
}

// HasValidationErrors returns a boolean if a field has been set.
func (o *GetIdPRes) HasValidationErrors() bool {
	if o != nil && !isNil(o.ValidationErrors) {
		return true
	}

	return false
}

// SetValidationErrors gets a reference to the given []string and assigns it to the ValidationErrors field.
func (o *GetIdPRes) SetValidationErrors(v []string) {
	o.ValidationErrors = v
}

func (o GetIdPRes) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if !isNil(o.Config) {
		toSerialize["config"] = o.Config
	}
	if !isNil(o.Error) {
		toSerialize["error"] = o.Error
	}
	if !isNil(o.Idp) {
		toSerialize["idp"] = o.Idp
	}
	if !isNil(o.ValidationErrors) {
		toSerialize["validationErrors"] = o.ValidationErrors
	}

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return json.Marshal(toSerialize)
}

func (o *GetIdPRes) UnmarshalJSON(bytes []byte) (err error) {
	varGetIdPRes := _GetIdPRes{}

	if err = json.Unmarshal(bytes, &varGetIdPRes); err == nil {
		*o = GetIdPRes(varGetIdPRes)
	}

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(bytes, &additionalProperties); err == nil {
		delete(additionalProperties, "config")
		delete(additionalProperties, "error")
		delete(additionalProperties, "idp")
		delete(additionalProperties, "validationErrors")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableGetIdPRes struct {
	value *GetIdPRes
	isSet bool
}

func (v NullableGetIdPRes) Get() *GetIdPRes {
	return v.value
}

func (v *NullableGetIdPRes) Set(val *GetIdPRes) {
	v.value = val
	v.isSet = true
}

func (v NullableGetIdPRes) IsSet() bool {
	return v.isSet
}

func (v *NullableGetIdPRes) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableGetIdPRes(val *GetIdPRes) *NullableGetIdPRes {
	return &NullableGetIdPRes{value: val, isSet: true}
}

func (v NullableGetIdPRes) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableGetIdPRes) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


