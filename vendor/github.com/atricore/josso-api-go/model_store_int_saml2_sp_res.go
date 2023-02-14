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

// StoreIntSaml2SpRes struct for StoreIntSaml2SpRes
type StoreIntSaml2SpRes struct {
	Error *string `json:"error,omitempty"`
	Sp *InternalSaml2ServiceProviderDTO `json:"sp,omitempty"`
	ValidationErrors []string `json:"validationErrors,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _StoreIntSaml2SpRes StoreIntSaml2SpRes

// NewStoreIntSaml2SpRes instantiates a new StoreIntSaml2SpRes object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewStoreIntSaml2SpRes() *StoreIntSaml2SpRes {
	this := StoreIntSaml2SpRes{}
	return &this
}

// NewStoreIntSaml2SpResWithDefaults instantiates a new StoreIntSaml2SpRes object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewStoreIntSaml2SpResWithDefaults() *StoreIntSaml2SpRes {
	this := StoreIntSaml2SpRes{}
	return &this
}

// GetError returns the Error field value if set, zero value otherwise.
func (o *StoreIntSaml2SpRes) GetError() string {
	if o == nil || isNil(o.Error) {
		var ret string
		return ret
	}
	return *o.Error
}

// GetErrorOk returns a tuple with the Error field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StoreIntSaml2SpRes) GetErrorOk() (*string, bool) {
	if o == nil || isNil(o.Error) {
    return nil, false
	}
	return o.Error, true
}

// HasError returns a boolean if a field has been set.
func (o *StoreIntSaml2SpRes) HasError() bool {
	if o != nil && !isNil(o.Error) {
		return true
	}

	return false
}

// SetError gets a reference to the given string and assigns it to the Error field.
func (o *StoreIntSaml2SpRes) SetError(v string) {
	o.Error = &v
}

// GetSp returns the Sp field value if set, zero value otherwise.
func (o *StoreIntSaml2SpRes) GetSp() InternalSaml2ServiceProviderDTO {
	if o == nil || isNil(o.Sp) {
		var ret InternalSaml2ServiceProviderDTO
		return ret
	}
	return *o.Sp
}

// GetSpOk returns a tuple with the Sp field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StoreIntSaml2SpRes) GetSpOk() (*InternalSaml2ServiceProviderDTO, bool) {
	if o == nil || isNil(o.Sp) {
    return nil, false
	}
	return o.Sp, true
}

// HasSp returns a boolean if a field has been set.
func (o *StoreIntSaml2SpRes) HasSp() bool {
	if o != nil && !isNil(o.Sp) {
		return true
	}

	return false
}

// SetSp gets a reference to the given InternalSaml2ServiceProviderDTO and assigns it to the Sp field.
func (o *StoreIntSaml2SpRes) SetSp(v InternalSaml2ServiceProviderDTO) {
	o.Sp = &v
}

// GetValidationErrors returns the ValidationErrors field value if set, zero value otherwise.
func (o *StoreIntSaml2SpRes) GetValidationErrors() []string {
	if o == nil || isNil(o.ValidationErrors) {
		var ret []string
		return ret
	}
	return o.ValidationErrors
}

// GetValidationErrorsOk returns a tuple with the ValidationErrors field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StoreIntSaml2SpRes) GetValidationErrorsOk() ([]string, bool) {
	if o == nil || isNil(o.ValidationErrors) {
    return nil, false
	}
	return o.ValidationErrors, true
}

// HasValidationErrors returns a boolean if a field has been set.
func (o *StoreIntSaml2SpRes) HasValidationErrors() bool {
	if o != nil && !isNil(o.ValidationErrors) {
		return true
	}

	return false
}

// SetValidationErrors gets a reference to the given []string and assigns it to the ValidationErrors field.
func (o *StoreIntSaml2SpRes) SetValidationErrors(v []string) {
	o.ValidationErrors = v
}

func (o StoreIntSaml2SpRes) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
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

func (o *StoreIntSaml2SpRes) UnmarshalJSON(bytes []byte) (err error) {
	varStoreIntSaml2SpRes := _StoreIntSaml2SpRes{}

	if err = json.Unmarshal(bytes, &varStoreIntSaml2SpRes); err == nil {
		*o = StoreIntSaml2SpRes(varStoreIntSaml2SpRes)
	}

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(bytes, &additionalProperties); err == nil {
		delete(additionalProperties, "error")
		delete(additionalProperties, "sp")
		delete(additionalProperties, "validationErrors")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableStoreIntSaml2SpRes struct {
	value *StoreIntSaml2SpRes
	isSet bool
}

func (v NullableStoreIntSaml2SpRes) Get() *StoreIntSaml2SpRes {
	return v.value
}

func (v *NullableStoreIntSaml2SpRes) Set(val *StoreIntSaml2SpRes) {
	v.value = val
	v.isSet = true
}

func (v NullableStoreIntSaml2SpRes) IsSet() bool {
	return v.isSet
}

func (v *NullableStoreIntSaml2SpRes) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableStoreIntSaml2SpRes(val *StoreIntSaml2SpRes) *NullableStoreIntSaml2SpRes {
	return &NullableStoreIntSaml2SpRes{value: val, isSet: true}
}

func (v NullableStoreIntSaml2SpRes) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableStoreIntSaml2SpRes) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


