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

// GetIdpGooglesRes struct for GetIdpGooglesRes
type GetIdpGooglesRes struct {
	Error *string `json:"error,omitempty"`
	Idps []GoogleOpenIDConnectIdentityProviderDTO `json:"idps,omitempty"`
	ValidationErrors []string `json:"validationErrors,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _GetIdpGooglesRes GetIdpGooglesRes

// NewGetIdpGooglesRes instantiates a new GetIdpGooglesRes object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewGetIdpGooglesRes() *GetIdpGooglesRes {
	this := GetIdpGooglesRes{}
	return &this
}

// NewGetIdpGooglesResWithDefaults instantiates a new GetIdpGooglesRes object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewGetIdpGooglesResWithDefaults() *GetIdpGooglesRes {
	this := GetIdpGooglesRes{}
	return &this
}

// GetError returns the Error field value if set, zero value otherwise.
func (o *GetIdpGooglesRes) GetError() string {
	if o == nil || isNil(o.Error) {
		var ret string
		return ret
	}
	return *o.Error
}

// GetErrorOk returns a tuple with the Error field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetIdpGooglesRes) GetErrorOk() (*string, bool) {
	if o == nil || isNil(o.Error) {
    return nil, false
	}
	return o.Error, true
}

// HasError returns a boolean if a field has been set.
func (o *GetIdpGooglesRes) HasError() bool {
	if o != nil && !isNil(o.Error) {
		return true
	}

	return false
}

// SetError gets a reference to the given string and assigns it to the Error field.
func (o *GetIdpGooglesRes) SetError(v string) {
	o.Error = &v
}

// GetIdps returns the Idps field value if set, zero value otherwise.
func (o *GetIdpGooglesRes) GetIdps() []GoogleOpenIDConnectIdentityProviderDTO {
	if o == nil || isNil(o.Idps) {
		var ret []GoogleOpenIDConnectIdentityProviderDTO
		return ret
	}
	return o.Idps
}

// GetIdpsOk returns a tuple with the Idps field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetIdpGooglesRes) GetIdpsOk() ([]GoogleOpenIDConnectIdentityProviderDTO, bool) {
	if o == nil || isNil(o.Idps) {
    return nil, false
	}
	return o.Idps, true
}

// HasIdps returns a boolean if a field has been set.
func (o *GetIdpGooglesRes) HasIdps() bool {
	if o != nil && !isNil(o.Idps) {
		return true
	}

	return false
}

// SetIdps gets a reference to the given []GoogleOpenIDConnectIdentityProviderDTO and assigns it to the Idps field.
func (o *GetIdpGooglesRes) SetIdps(v []GoogleOpenIDConnectIdentityProviderDTO) {
	o.Idps = v
}

// GetValidationErrors returns the ValidationErrors field value if set, zero value otherwise.
func (o *GetIdpGooglesRes) GetValidationErrors() []string {
	if o == nil || isNil(o.ValidationErrors) {
		var ret []string
		return ret
	}
	return o.ValidationErrors
}

// GetValidationErrorsOk returns a tuple with the ValidationErrors field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetIdpGooglesRes) GetValidationErrorsOk() ([]string, bool) {
	if o == nil || isNil(o.ValidationErrors) {
    return nil, false
	}
	return o.ValidationErrors, true
}

// HasValidationErrors returns a boolean if a field has been set.
func (o *GetIdpGooglesRes) HasValidationErrors() bool {
	if o != nil && !isNil(o.ValidationErrors) {
		return true
	}

	return false
}

// SetValidationErrors gets a reference to the given []string and assigns it to the ValidationErrors field.
func (o *GetIdpGooglesRes) SetValidationErrors(v []string) {
	o.ValidationErrors = v
}

func (o GetIdpGooglesRes) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if !isNil(o.Error) {
		toSerialize["error"] = o.Error
	}
	if !isNil(o.Idps) {
		toSerialize["idps"] = o.Idps
	}
	if !isNil(o.ValidationErrors) {
		toSerialize["validationErrors"] = o.ValidationErrors
	}

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return json.Marshal(toSerialize)
}

func (o *GetIdpGooglesRes) UnmarshalJSON(bytes []byte) (err error) {
	varGetIdpGooglesRes := _GetIdpGooglesRes{}

	if err = json.Unmarshal(bytes, &varGetIdpGooglesRes); err == nil {
		*o = GetIdpGooglesRes(varGetIdpGooglesRes)
	}

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(bytes, &additionalProperties); err == nil {
		delete(additionalProperties, "error")
		delete(additionalProperties, "idps")
		delete(additionalProperties, "validationErrors")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableGetIdpGooglesRes struct {
	value *GetIdpGooglesRes
	isSet bool
}

func (v NullableGetIdpGooglesRes) Get() *GetIdpGooglesRes {
	return v.value
}

func (v *NullableGetIdpGooglesRes) Set(val *GetIdpGooglesRes) {
	v.value = val
	v.isSet = true
}

func (v NullableGetIdpGooglesRes) IsSet() bool {
	return v.isSet
}

func (v *NullableGetIdpGooglesRes) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableGetIdpGooglesRes(val *GetIdpGooglesRes) *NullableGetIdpGooglesRes {
	return &NullableGetIdpGooglesRes{value: val, isSet: true}
}

func (v NullableGetIdpGooglesRes) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableGetIdpGooglesRes) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


