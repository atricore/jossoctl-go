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

// GetIdSourceDbRes struct for GetIdSourceDbRes
type GetIdSourceDbRes struct {
	Error *string `json:"error,omitempty"`
	IdSourceDb *DbIdentitySourceDTO `json:"idSourceDb,omitempty"`
	ValidationErrors []string `json:"validationErrors,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _GetIdSourceDbRes GetIdSourceDbRes

// NewGetIdSourceDbRes instantiates a new GetIdSourceDbRes object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewGetIdSourceDbRes() *GetIdSourceDbRes {
	this := GetIdSourceDbRes{}
	return &this
}

// NewGetIdSourceDbResWithDefaults instantiates a new GetIdSourceDbRes object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewGetIdSourceDbResWithDefaults() *GetIdSourceDbRes {
	this := GetIdSourceDbRes{}
	return &this
}

// GetError returns the Error field value if set, zero value otherwise.
func (o *GetIdSourceDbRes) GetError() string {
	if o == nil || isNil(o.Error) {
		var ret string
		return ret
	}
	return *o.Error
}

// GetErrorOk returns a tuple with the Error field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetIdSourceDbRes) GetErrorOk() (*string, bool) {
	if o == nil || isNil(o.Error) {
    return nil, false
	}
	return o.Error, true
}

// HasError returns a boolean if a field has been set.
func (o *GetIdSourceDbRes) HasError() bool {
	if o != nil && !isNil(o.Error) {
		return true
	}

	return false
}

// SetError gets a reference to the given string and assigns it to the Error field.
func (o *GetIdSourceDbRes) SetError(v string) {
	o.Error = &v
}

// GetIdSourceDb returns the IdSourceDb field value if set, zero value otherwise.
func (o *GetIdSourceDbRes) GetIdSourceDb() DbIdentitySourceDTO {
	if o == nil || isNil(o.IdSourceDb) {
		var ret DbIdentitySourceDTO
		return ret
	}
	return *o.IdSourceDb
}

// GetIdSourceDbOk returns a tuple with the IdSourceDb field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetIdSourceDbRes) GetIdSourceDbOk() (*DbIdentitySourceDTO, bool) {
	if o == nil || isNil(o.IdSourceDb) {
    return nil, false
	}
	return o.IdSourceDb, true
}

// HasIdSourceDb returns a boolean if a field has been set.
func (o *GetIdSourceDbRes) HasIdSourceDb() bool {
	if o != nil && !isNil(o.IdSourceDb) {
		return true
	}

	return false
}

// SetIdSourceDb gets a reference to the given DbIdentitySourceDTO and assigns it to the IdSourceDb field.
func (o *GetIdSourceDbRes) SetIdSourceDb(v DbIdentitySourceDTO) {
	o.IdSourceDb = &v
}

// GetValidationErrors returns the ValidationErrors field value if set, zero value otherwise.
func (o *GetIdSourceDbRes) GetValidationErrors() []string {
	if o == nil || isNil(o.ValidationErrors) {
		var ret []string
		return ret
	}
	return o.ValidationErrors
}

// GetValidationErrorsOk returns a tuple with the ValidationErrors field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetIdSourceDbRes) GetValidationErrorsOk() ([]string, bool) {
	if o == nil || isNil(o.ValidationErrors) {
    return nil, false
	}
	return o.ValidationErrors, true
}

// HasValidationErrors returns a boolean if a field has been set.
func (o *GetIdSourceDbRes) HasValidationErrors() bool {
	if o != nil && !isNil(o.ValidationErrors) {
		return true
	}

	return false
}

// SetValidationErrors gets a reference to the given []string and assigns it to the ValidationErrors field.
func (o *GetIdSourceDbRes) SetValidationErrors(v []string) {
	o.ValidationErrors = v
}

func (o GetIdSourceDbRes) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if !isNil(o.Error) {
		toSerialize["error"] = o.Error
	}
	if !isNil(o.IdSourceDb) {
		toSerialize["idSourceDb"] = o.IdSourceDb
	}
	if !isNil(o.ValidationErrors) {
		toSerialize["validationErrors"] = o.ValidationErrors
	}

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return json.Marshal(toSerialize)
}

func (o *GetIdSourceDbRes) UnmarshalJSON(bytes []byte) (err error) {
	varGetIdSourceDbRes := _GetIdSourceDbRes{}

	if err = json.Unmarshal(bytes, &varGetIdSourceDbRes); err == nil {
		*o = GetIdSourceDbRes(varGetIdSourceDbRes)
	}

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(bytes, &additionalProperties); err == nil {
		delete(additionalProperties, "error")
		delete(additionalProperties, "idSourceDb")
		delete(additionalProperties, "validationErrors")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableGetIdSourceDbRes struct {
	value *GetIdSourceDbRes
	isSet bool
}

func (v NullableGetIdSourceDbRes) Get() *GetIdSourceDbRes {
	return v.value
}

func (v *NullableGetIdSourceDbRes) Set(val *GetIdSourceDbRes) {
	v.value = val
	v.isSet = true
}

func (v NullableGetIdSourceDbRes) IsSet() bool {
	return v.isSet
}

func (v *NullableGetIdSourceDbRes) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableGetIdSourceDbRes(val *GetIdSourceDbRes) *NullableGetIdSourceDbRes {
	return &NullableGetIdSourceDbRes{value: val, isSet: true}
}

func (v NullableGetIdSourceDbRes) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableGetIdSourceDbRes) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


