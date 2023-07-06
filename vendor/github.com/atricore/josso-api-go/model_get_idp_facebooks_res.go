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

// GetIdpFacebooksRes struct for GetIdpFacebooksRes
type GetIdpFacebooksRes struct {
	Error *string `json:"error,omitempty"`
	Idps []FacebookOpenIDConnectIdentityProviderDTO `json:"idps,omitempty"`
	ValidationErrors []string `json:"validationErrors,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _GetIdpFacebooksRes GetIdpFacebooksRes

// NewGetIdpFacebooksRes instantiates a new GetIdpFacebooksRes object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewGetIdpFacebooksRes() *GetIdpFacebooksRes {
	this := GetIdpFacebooksRes{}
	return &this
}

// NewGetIdpFacebooksResWithDefaults instantiates a new GetIdpFacebooksRes object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewGetIdpFacebooksResWithDefaults() *GetIdpFacebooksRes {
	this := GetIdpFacebooksRes{}
	return &this
}

// GetError returns the Error field value if set, zero value otherwise.
func (o *GetIdpFacebooksRes) GetError() string {
	if o == nil || isNil(o.Error) {
		var ret string
		return ret
	}
	return *o.Error
}

// GetErrorOk returns a tuple with the Error field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetIdpFacebooksRes) GetErrorOk() (*string, bool) {
	if o == nil || isNil(o.Error) {
    return nil, false
	}
	return o.Error, true
}

// HasError returns a boolean if a field has been set.
func (o *GetIdpFacebooksRes) HasError() bool {
	if o != nil && !isNil(o.Error) {
		return true
	}

	return false
}

// SetError gets a reference to the given string and assigns it to the Error field.
func (o *GetIdpFacebooksRes) SetError(v string) {
	o.Error = &v
}

// GetIdps returns the Idps field value if set, zero value otherwise.
func (o *GetIdpFacebooksRes) GetIdps() []FacebookOpenIDConnectIdentityProviderDTO {
	if o == nil || isNil(o.Idps) {
		var ret []FacebookOpenIDConnectIdentityProviderDTO
		return ret
	}
	return o.Idps
}

// GetIdpsOk returns a tuple with the Idps field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetIdpFacebooksRes) GetIdpsOk() ([]FacebookOpenIDConnectIdentityProviderDTO, bool) {
	if o == nil || isNil(o.Idps) {
    return nil, false
	}
	return o.Idps, true
}

// HasIdps returns a boolean if a field has been set.
func (o *GetIdpFacebooksRes) HasIdps() bool {
	if o != nil && !isNil(o.Idps) {
		return true
	}

	return false
}

// SetIdps gets a reference to the given []FacebookOpenIDConnectIdentityProviderDTO and assigns it to the Idps field.
func (o *GetIdpFacebooksRes) SetIdps(v []FacebookOpenIDConnectIdentityProviderDTO) {
	o.Idps = v
}

// GetValidationErrors returns the ValidationErrors field value if set, zero value otherwise.
func (o *GetIdpFacebooksRes) GetValidationErrors() []string {
	if o == nil || isNil(o.ValidationErrors) {
		var ret []string
		return ret
	}
	return o.ValidationErrors
}

// GetValidationErrorsOk returns a tuple with the ValidationErrors field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetIdpFacebooksRes) GetValidationErrorsOk() ([]string, bool) {
	if o == nil || isNil(o.ValidationErrors) {
    return nil, false
	}
	return o.ValidationErrors, true
}

// HasValidationErrors returns a boolean if a field has been set.
func (o *GetIdpFacebooksRes) HasValidationErrors() bool {
	if o != nil && !isNil(o.ValidationErrors) {
		return true
	}

	return false
}

// SetValidationErrors gets a reference to the given []string and assigns it to the ValidationErrors field.
func (o *GetIdpFacebooksRes) SetValidationErrors(v []string) {
	o.ValidationErrors = v
}

func (o GetIdpFacebooksRes) MarshalJSON() ([]byte, error) {
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

func (o *GetIdpFacebooksRes) UnmarshalJSON(bytes []byte) (err error) {
	varGetIdpFacebooksRes := _GetIdpFacebooksRes{}

	if err = json.Unmarshal(bytes, &varGetIdpFacebooksRes); err == nil {
		*o = GetIdpFacebooksRes(varGetIdpFacebooksRes)
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

type NullableGetIdpFacebooksRes struct {
	value *GetIdpFacebooksRes
	isSet bool
}

func (v NullableGetIdpFacebooksRes) Get() *GetIdpFacebooksRes {
	return v.value
}

func (v *NullableGetIdpFacebooksRes) Set(val *GetIdpFacebooksRes) {
	v.value = val
	v.isSet = true
}

func (v NullableGetIdpFacebooksRes) IsSet() bool {
	return v.isSet
}

func (v *NullableGetIdpFacebooksRes) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableGetIdpFacebooksRes(val *GetIdpFacebooksRes) *NullableGetIdpFacebooksRes {
	return &NullableGetIdpFacebooksRes{value: val, isSet: true}
}

func (v NullableGetIdpFacebooksRes) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableGetIdpFacebooksRes) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


