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

// GetIdpAzureRes struct for GetIdpAzureRes
type GetIdpAzureRes struct {
	Error *string `json:"error,omitempty"`
	Idp *AzureOpenIDConnectIdentityProviderDTO `json:"idp,omitempty"`
	ValidationErrors []string `json:"validationErrors,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _GetIdpAzureRes GetIdpAzureRes

// NewGetIdpAzureRes instantiates a new GetIdpAzureRes object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewGetIdpAzureRes() *GetIdpAzureRes {
	this := GetIdpAzureRes{}
	return &this
}

// NewGetIdpAzureResWithDefaults instantiates a new GetIdpAzureRes object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewGetIdpAzureResWithDefaults() *GetIdpAzureRes {
	this := GetIdpAzureRes{}
	return &this
}

// GetError returns the Error field value if set, zero value otherwise.
func (o *GetIdpAzureRes) GetError() string {
	if o == nil || isNil(o.Error) {
		var ret string
		return ret
	}
	return *o.Error
}

// GetErrorOk returns a tuple with the Error field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetIdpAzureRes) GetErrorOk() (*string, bool) {
	if o == nil || isNil(o.Error) {
    return nil, false
	}
	return o.Error, true
}

// HasError returns a boolean if a field has been set.
func (o *GetIdpAzureRes) HasError() bool {
	if o != nil && !isNil(o.Error) {
		return true
	}

	return false
}

// SetError gets a reference to the given string and assigns it to the Error field.
func (o *GetIdpAzureRes) SetError(v string) {
	o.Error = &v
}

// GetIdp returns the Idp field value if set, zero value otherwise.
func (o *GetIdpAzureRes) GetIdp() AzureOpenIDConnectIdentityProviderDTO {
	if o == nil || isNil(o.Idp) {
		var ret AzureOpenIDConnectIdentityProviderDTO
		return ret
	}
	return *o.Idp
}

// GetIdpOk returns a tuple with the Idp field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetIdpAzureRes) GetIdpOk() (*AzureOpenIDConnectIdentityProviderDTO, bool) {
	if o == nil || isNil(o.Idp) {
    return nil, false
	}
	return o.Idp, true
}

// HasIdp returns a boolean if a field has been set.
func (o *GetIdpAzureRes) HasIdp() bool {
	if o != nil && !isNil(o.Idp) {
		return true
	}

	return false
}

// SetIdp gets a reference to the given AzureOpenIDConnectIdentityProviderDTO and assigns it to the Idp field.
func (o *GetIdpAzureRes) SetIdp(v AzureOpenIDConnectIdentityProviderDTO) {
	o.Idp = &v
}

// GetValidationErrors returns the ValidationErrors field value if set, zero value otherwise.
func (o *GetIdpAzureRes) GetValidationErrors() []string {
	if o == nil || isNil(o.ValidationErrors) {
		var ret []string
		return ret
	}
	return o.ValidationErrors
}

// GetValidationErrorsOk returns a tuple with the ValidationErrors field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetIdpAzureRes) GetValidationErrorsOk() ([]string, bool) {
	if o == nil || isNil(o.ValidationErrors) {
    return nil, false
	}
	return o.ValidationErrors, true
}

// HasValidationErrors returns a boolean if a field has been set.
func (o *GetIdpAzureRes) HasValidationErrors() bool {
	if o != nil && !isNil(o.ValidationErrors) {
		return true
	}

	return false
}

// SetValidationErrors gets a reference to the given []string and assigns it to the ValidationErrors field.
func (o *GetIdpAzureRes) SetValidationErrors(v []string) {
	o.ValidationErrors = v
}

func (o GetIdpAzureRes) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
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

func (o *GetIdpAzureRes) UnmarshalJSON(bytes []byte) (err error) {
	varGetIdpAzureRes := _GetIdpAzureRes{}

	if err = json.Unmarshal(bytes, &varGetIdpAzureRes); err == nil {
		*o = GetIdpAzureRes(varGetIdpAzureRes)
	}

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(bytes, &additionalProperties); err == nil {
		delete(additionalProperties, "error")
		delete(additionalProperties, "idp")
		delete(additionalProperties, "validationErrors")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableGetIdpAzureRes struct {
	value *GetIdpAzureRes
	isSet bool
}

func (v NullableGetIdpAzureRes) Get() *GetIdpAzureRes {
	return v.value
}

func (v *NullableGetIdpAzureRes) Set(val *GetIdpAzureRes) {
	v.value = val
	v.isSet = true
}

func (v NullableGetIdpAzureRes) IsSet() bool {
	return v.isSet
}

func (v *NullableGetIdpAzureRes) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableGetIdpAzureRes(val *GetIdpAzureRes) *NullableGetIdpAzureRes {
	return &NullableGetIdpAzureRes{value: val, isSet: true}
}

func (v NullableGetIdpAzureRes) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableGetIdpAzureRes) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


