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

// AttributeMapperProfileDTO struct for AttributeMapperProfileDTO
type AttributeMapperProfileDTO struct {
	AttributeMaps []AttributeMappingDTO `json:"attributeMaps,omitempty"`
	ElementId *string `json:"elementId,omitempty"`
	Id *int64 `json:"id,omitempty"`
	IncludeNonMappedProperties *bool `json:"includeNonMappedProperties,omitempty"`
	Name *string `json:"name,omitempty"`
	ProfileType *string `json:"profileType,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _AttributeMapperProfileDTO AttributeMapperProfileDTO

// NewAttributeMapperProfileDTO instantiates a new AttributeMapperProfileDTO object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAttributeMapperProfileDTO() *AttributeMapperProfileDTO {
	this := AttributeMapperProfileDTO{}
	return &this
}

// NewAttributeMapperProfileDTOWithDefaults instantiates a new AttributeMapperProfileDTO object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAttributeMapperProfileDTOWithDefaults() *AttributeMapperProfileDTO {
	this := AttributeMapperProfileDTO{}
	return &this
}

// GetAttributeMaps returns the AttributeMaps field value if set, zero value otherwise.
func (o *AttributeMapperProfileDTO) GetAttributeMaps() []AttributeMappingDTO {
	if o == nil || isNil(o.AttributeMaps) {
		var ret []AttributeMappingDTO
		return ret
	}
	return o.AttributeMaps
}

// GetAttributeMapsOk returns a tuple with the AttributeMaps field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AttributeMapperProfileDTO) GetAttributeMapsOk() ([]AttributeMappingDTO, bool) {
	if o == nil || isNil(o.AttributeMaps) {
    return nil, false
	}
	return o.AttributeMaps, true
}

// HasAttributeMaps returns a boolean if a field has been set.
func (o *AttributeMapperProfileDTO) HasAttributeMaps() bool {
	if o != nil && !isNil(o.AttributeMaps) {
		return true
	}

	return false
}

// SetAttributeMaps gets a reference to the given []AttributeMappingDTO and assigns it to the AttributeMaps field.
func (o *AttributeMapperProfileDTO) SetAttributeMaps(v []AttributeMappingDTO) {
	o.AttributeMaps = v
}

// GetElementId returns the ElementId field value if set, zero value otherwise.
func (o *AttributeMapperProfileDTO) GetElementId() string {
	if o == nil || isNil(o.ElementId) {
		var ret string
		return ret
	}
	return *o.ElementId
}

// GetElementIdOk returns a tuple with the ElementId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AttributeMapperProfileDTO) GetElementIdOk() (*string, bool) {
	if o == nil || isNil(o.ElementId) {
    return nil, false
	}
	return o.ElementId, true
}

// HasElementId returns a boolean if a field has been set.
func (o *AttributeMapperProfileDTO) HasElementId() bool {
	if o != nil && !isNil(o.ElementId) {
		return true
	}

	return false
}

// SetElementId gets a reference to the given string and assigns it to the ElementId field.
func (o *AttributeMapperProfileDTO) SetElementId(v string) {
	o.ElementId = &v
}

// GetId returns the Id field value if set, zero value otherwise.
func (o *AttributeMapperProfileDTO) GetId() int64 {
	if o == nil || isNil(o.Id) {
		var ret int64
		return ret
	}
	return *o.Id
}

// GetIdOk returns a tuple with the Id field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AttributeMapperProfileDTO) GetIdOk() (*int64, bool) {
	if o == nil || isNil(o.Id) {
    return nil, false
	}
	return o.Id, true
}

// HasId returns a boolean if a field has been set.
func (o *AttributeMapperProfileDTO) HasId() bool {
	if o != nil && !isNil(o.Id) {
		return true
	}

	return false
}

// SetId gets a reference to the given int64 and assigns it to the Id field.
func (o *AttributeMapperProfileDTO) SetId(v int64) {
	o.Id = &v
}

// GetIncludeNonMappedProperties returns the IncludeNonMappedProperties field value if set, zero value otherwise.
func (o *AttributeMapperProfileDTO) GetIncludeNonMappedProperties() bool {
	if o == nil || isNil(o.IncludeNonMappedProperties) {
		var ret bool
		return ret
	}
	return *o.IncludeNonMappedProperties
}

// GetIncludeNonMappedPropertiesOk returns a tuple with the IncludeNonMappedProperties field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AttributeMapperProfileDTO) GetIncludeNonMappedPropertiesOk() (*bool, bool) {
	if o == nil || isNil(o.IncludeNonMappedProperties) {
    return nil, false
	}
	return o.IncludeNonMappedProperties, true
}

// HasIncludeNonMappedProperties returns a boolean if a field has been set.
func (o *AttributeMapperProfileDTO) HasIncludeNonMappedProperties() bool {
	if o != nil && !isNil(o.IncludeNonMappedProperties) {
		return true
	}

	return false
}

// SetIncludeNonMappedProperties gets a reference to the given bool and assigns it to the IncludeNonMappedProperties field.
func (o *AttributeMapperProfileDTO) SetIncludeNonMappedProperties(v bool) {
	o.IncludeNonMappedProperties = &v
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *AttributeMapperProfileDTO) GetName() string {
	if o == nil || isNil(o.Name) {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AttributeMapperProfileDTO) GetNameOk() (*string, bool) {
	if o == nil || isNil(o.Name) {
    return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *AttributeMapperProfileDTO) HasName() bool {
	if o != nil && !isNil(o.Name) {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *AttributeMapperProfileDTO) SetName(v string) {
	o.Name = &v
}

// GetProfileType returns the ProfileType field value if set, zero value otherwise.
func (o *AttributeMapperProfileDTO) GetProfileType() string {
	if o == nil || isNil(o.ProfileType) {
		var ret string
		return ret
	}
	return *o.ProfileType
}

// GetProfileTypeOk returns a tuple with the ProfileType field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AttributeMapperProfileDTO) GetProfileTypeOk() (*string, bool) {
	if o == nil || isNil(o.ProfileType) {
    return nil, false
	}
	return o.ProfileType, true
}

// HasProfileType returns a boolean if a field has been set.
func (o *AttributeMapperProfileDTO) HasProfileType() bool {
	if o != nil && !isNil(o.ProfileType) {
		return true
	}

	return false
}

// SetProfileType gets a reference to the given string and assigns it to the ProfileType field.
func (o *AttributeMapperProfileDTO) SetProfileType(v string) {
	o.ProfileType = &v
}

func (o AttributeMapperProfileDTO) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if !isNil(o.AttributeMaps) {
		toSerialize["attributeMaps"] = o.AttributeMaps
	}
	if !isNil(o.ElementId) {
		toSerialize["elementId"] = o.ElementId
	}
	if !isNil(o.Id) {
		toSerialize["id"] = o.Id
	}
	if !isNil(o.IncludeNonMappedProperties) {
		toSerialize["includeNonMappedProperties"] = o.IncludeNonMappedProperties
	}
	if !isNil(o.Name) {
		toSerialize["name"] = o.Name
	}
	if !isNil(o.ProfileType) {
		toSerialize["profileType"] = o.ProfileType
	}

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return json.Marshal(toSerialize)
}

func (o *AttributeMapperProfileDTO) UnmarshalJSON(bytes []byte) (err error) {
	varAttributeMapperProfileDTO := _AttributeMapperProfileDTO{}

	if err = json.Unmarshal(bytes, &varAttributeMapperProfileDTO); err == nil {
		*o = AttributeMapperProfileDTO(varAttributeMapperProfileDTO)
	}

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(bytes, &additionalProperties); err == nil {
		delete(additionalProperties, "attributeMaps")
		delete(additionalProperties, "elementId")
		delete(additionalProperties, "id")
		delete(additionalProperties, "includeNonMappedProperties")
		delete(additionalProperties, "name")
		delete(additionalProperties, "profileType")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableAttributeMapperProfileDTO struct {
	value *AttributeMapperProfileDTO
	isSet bool
}

func (v NullableAttributeMapperProfileDTO) Get() *AttributeMapperProfileDTO {
	return v.value
}

func (v *NullableAttributeMapperProfileDTO) Set(val *AttributeMapperProfileDTO) {
	v.value = val
	v.isSet = true
}

func (v NullableAttributeMapperProfileDTO) IsSet() bool {
	return v.isSet
}

func (v *NullableAttributeMapperProfileDTO) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAttributeMapperProfileDTO(val *AttributeMapperProfileDTO) *NullableAttributeMapperProfileDTO {
	return &NullableAttributeMapperProfileDTO{value: val, isSet: true}
}

func (v NullableAttributeMapperProfileDTO) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAttributeMapperProfileDTO) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


