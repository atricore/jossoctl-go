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

// KeystoreDTO struct for KeystoreDTO
type KeystoreDTO struct {
	CertificateAlias *string `json:"certificateAlias,omitempty"`
	DisplayName *string `json:"displayName,omitempty"`
	ElementId *string `json:"elementId,omitempty"`
	Id *int64 `json:"id,omitempty"`
	KeystorePassOnly *bool `json:"keystorePassOnly,omitempty"`
	Name *string `json:"name,omitempty"`
	Password *string `json:"password,omitempty"`
	PrivateKeyName *string `json:"privateKeyName,omitempty"`
	PrivateKeyPassword *string `json:"privateKeyPassword,omitempty"`
	Store *ResourceDTO `json:"store,omitempty"`
	Type *string `json:"type,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _KeystoreDTO KeystoreDTO

// NewKeystoreDTO instantiates a new KeystoreDTO object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewKeystoreDTO() *KeystoreDTO {
	this := KeystoreDTO{}
	return &this
}

// NewKeystoreDTOWithDefaults instantiates a new KeystoreDTO object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewKeystoreDTOWithDefaults() *KeystoreDTO {
	this := KeystoreDTO{}
	return &this
}

// GetCertificateAlias returns the CertificateAlias field value if set, zero value otherwise.
func (o *KeystoreDTO) GetCertificateAlias() string {
	if o == nil || isNil(o.CertificateAlias) {
		var ret string
		return ret
	}
	return *o.CertificateAlias
}

// GetCertificateAliasOk returns a tuple with the CertificateAlias field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KeystoreDTO) GetCertificateAliasOk() (*string, bool) {
	if o == nil || isNil(o.CertificateAlias) {
    return nil, false
	}
	return o.CertificateAlias, true
}

// HasCertificateAlias returns a boolean if a field has been set.
func (o *KeystoreDTO) HasCertificateAlias() bool {
	if o != nil && !isNil(o.CertificateAlias) {
		return true
	}

	return false
}

// SetCertificateAlias gets a reference to the given string and assigns it to the CertificateAlias field.
func (o *KeystoreDTO) SetCertificateAlias(v string) {
	o.CertificateAlias = &v
}

// GetDisplayName returns the DisplayName field value if set, zero value otherwise.
func (o *KeystoreDTO) GetDisplayName() string {
	if o == nil || isNil(o.DisplayName) {
		var ret string
		return ret
	}
	return *o.DisplayName
}

// GetDisplayNameOk returns a tuple with the DisplayName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KeystoreDTO) GetDisplayNameOk() (*string, bool) {
	if o == nil || isNil(o.DisplayName) {
    return nil, false
	}
	return o.DisplayName, true
}

// HasDisplayName returns a boolean if a field has been set.
func (o *KeystoreDTO) HasDisplayName() bool {
	if o != nil && !isNil(o.DisplayName) {
		return true
	}

	return false
}

// SetDisplayName gets a reference to the given string and assigns it to the DisplayName field.
func (o *KeystoreDTO) SetDisplayName(v string) {
	o.DisplayName = &v
}

// GetElementId returns the ElementId field value if set, zero value otherwise.
func (o *KeystoreDTO) GetElementId() string {
	if o == nil || isNil(o.ElementId) {
		var ret string
		return ret
	}
	return *o.ElementId
}

// GetElementIdOk returns a tuple with the ElementId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KeystoreDTO) GetElementIdOk() (*string, bool) {
	if o == nil || isNil(o.ElementId) {
    return nil, false
	}
	return o.ElementId, true
}

// HasElementId returns a boolean if a field has been set.
func (o *KeystoreDTO) HasElementId() bool {
	if o != nil && !isNil(o.ElementId) {
		return true
	}

	return false
}

// SetElementId gets a reference to the given string and assigns it to the ElementId field.
func (o *KeystoreDTO) SetElementId(v string) {
	o.ElementId = &v
}

// GetId returns the Id field value if set, zero value otherwise.
func (o *KeystoreDTO) GetId() int64 {
	if o == nil || isNil(o.Id) {
		var ret int64
		return ret
	}
	return *o.Id
}

// GetIdOk returns a tuple with the Id field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KeystoreDTO) GetIdOk() (*int64, bool) {
	if o == nil || isNil(o.Id) {
    return nil, false
	}
	return o.Id, true
}

// HasId returns a boolean if a field has been set.
func (o *KeystoreDTO) HasId() bool {
	if o != nil && !isNil(o.Id) {
		return true
	}

	return false
}

// SetId gets a reference to the given int64 and assigns it to the Id field.
func (o *KeystoreDTO) SetId(v int64) {
	o.Id = &v
}

// GetKeystorePassOnly returns the KeystorePassOnly field value if set, zero value otherwise.
func (o *KeystoreDTO) GetKeystorePassOnly() bool {
	if o == nil || isNil(o.KeystorePassOnly) {
		var ret bool
		return ret
	}
	return *o.KeystorePassOnly
}

// GetKeystorePassOnlyOk returns a tuple with the KeystorePassOnly field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KeystoreDTO) GetKeystorePassOnlyOk() (*bool, bool) {
	if o == nil || isNil(o.KeystorePassOnly) {
    return nil, false
	}
	return o.KeystorePassOnly, true
}

// HasKeystorePassOnly returns a boolean if a field has been set.
func (o *KeystoreDTO) HasKeystorePassOnly() bool {
	if o != nil && !isNil(o.KeystorePassOnly) {
		return true
	}

	return false
}

// SetKeystorePassOnly gets a reference to the given bool and assigns it to the KeystorePassOnly field.
func (o *KeystoreDTO) SetKeystorePassOnly(v bool) {
	o.KeystorePassOnly = &v
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *KeystoreDTO) GetName() string {
	if o == nil || isNil(o.Name) {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KeystoreDTO) GetNameOk() (*string, bool) {
	if o == nil || isNil(o.Name) {
    return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *KeystoreDTO) HasName() bool {
	if o != nil && !isNil(o.Name) {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *KeystoreDTO) SetName(v string) {
	o.Name = &v
}

// GetPassword returns the Password field value if set, zero value otherwise.
func (o *KeystoreDTO) GetPassword() string {
	if o == nil || isNil(o.Password) {
		var ret string
		return ret
	}
	return *o.Password
}

// GetPasswordOk returns a tuple with the Password field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KeystoreDTO) GetPasswordOk() (*string, bool) {
	if o == nil || isNil(o.Password) {
    return nil, false
	}
	return o.Password, true
}

// HasPassword returns a boolean if a field has been set.
func (o *KeystoreDTO) HasPassword() bool {
	if o != nil && !isNil(o.Password) {
		return true
	}

	return false
}

// SetPassword gets a reference to the given string and assigns it to the Password field.
func (o *KeystoreDTO) SetPassword(v string) {
	o.Password = &v
}

// GetPrivateKeyName returns the PrivateKeyName field value if set, zero value otherwise.
func (o *KeystoreDTO) GetPrivateKeyName() string {
	if o == nil || isNil(o.PrivateKeyName) {
		var ret string
		return ret
	}
	return *o.PrivateKeyName
}

// GetPrivateKeyNameOk returns a tuple with the PrivateKeyName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KeystoreDTO) GetPrivateKeyNameOk() (*string, bool) {
	if o == nil || isNil(o.PrivateKeyName) {
    return nil, false
	}
	return o.PrivateKeyName, true
}

// HasPrivateKeyName returns a boolean if a field has been set.
func (o *KeystoreDTO) HasPrivateKeyName() bool {
	if o != nil && !isNil(o.PrivateKeyName) {
		return true
	}

	return false
}

// SetPrivateKeyName gets a reference to the given string and assigns it to the PrivateKeyName field.
func (o *KeystoreDTO) SetPrivateKeyName(v string) {
	o.PrivateKeyName = &v
}

// GetPrivateKeyPassword returns the PrivateKeyPassword field value if set, zero value otherwise.
func (o *KeystoreDTO) GetPrivateKeyPassword() string {
	if o == nil || isNil(o.PrivateKeyPassword) {
		var ret string
		return ret
	}
	return *o.PrivateKeyPassword
}

// GetPrivateKeyPasswordOk returns a tuple with the PrivateKeyPassword field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KeystoreDTO) GetPrivateKeyPasswordOk() (*string, bool) {
	if o == nil || isNil(o.PrivateKeyPassword) {
    return nil, false
	}
	return o.PrivateKeyPassword, true
}

// HasPrivateKeyPassword returns a boolean if a field has been set.
func (o *KeystoreDTO) HasPrivateKeyPassword() bool {
	if o != nil && !isNil(o.PrivateKeyPassword) {
		return true
	}

	return false
}

// SetPrivateKeyPassword gets a reference to the given string and assigns it to the PrivateKeyPassword field.
func (o *KeystoreDTO) SetPrivateKeyPassword(v string) {
	o.PrivateKeyPassword = &v
}

// GetStore returns the Store field value if set, zero value otherwise.
func (o *KeystoreDTO) GetStore() ResourceDTO {
	if o == nil || isNil(o.Store) {
		var ret ResourceDTO
		return ret
	}
	return *o.Store
}

// GetStoreOk returns a tuple with the Store field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KeystoreDTO) GetStoreOk() (*ResourceDTO, bool) {
	if o == nil || isNil(o.Store) {
    return nil, false
	}
	return o.Store, true
}

// HasStore returns a boolean if a field has been set.
func (o *KeystoreDTO) HasStore() bool {
	if o != nil && !isNil(o.Store) {
		return true
	}

	return false
}

// SetStore gets a reference to the given ResourceDTO and assigns it to the Store field.
func (o *KeystoreDTO) SetStore(v ResourceDTO) {
	o.Store = &v
}

// GetType returns the Type field value if set, zero value otherwise.
func (o *KeystoreDTO) GetType() string {
	if o == nil || isNil(o.Type) {
		var ret string
		return ret
	}
	return *o.Type
}

// GetTypeOk returns a tuple with the Type field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KeystoreDTO) GetTypeOk() (*string, bool) {
	if o == nil || isNil(o.Type) {
    return nil, false
	}
	return o.Type, true
}

// HasType returns a boolean if a field has been set.
func (o *KeystoreDTO) HasType() bool {
	if o != nil && !isNil(o.Type) {
		return true
	}

	return false
}

// SetType gets a reference to the given string and assigns it to the Type field.
func (o *KeystoreDTO) SetType(v string) {
	o.Type = &v
}

func (o KeystoreDTO) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if !isNil(o.CertificateAlias) {
		toSerialize["certificateAlias"] = o.CertificateAlias
	}
	if !isNil(o.DisplayName) {
		toSerialize["displayName"] = o.DisplayName
	}
	if !isNil(o.ElementId) {
		toSerialize["elementId"] = o.ElementId
	}
	if !isNil(o.Id) {
		toSerialize["id"] = o.Id
	}
	if !isNil(o.KeystorePassOnly) {
		toSerialize["keystorePassOnly"] = o.KeystorePassOnly
	}
	if !isNil(o.Name) {
		toSerialize["name"] = o.Name
	}
	if !isNil(o.Password) {
		toSerialize["password"] = o.Password
	}
	if !isNil(o.PrivateKeyName) {
		toSerialize["privateKeyName"] = o.PrivateKeyName
	}
	if !isNil(o.PrivateKeyPassword) {
		toSerialize["privateKeyPassword"] = o.PrivateKeyPassword
	}
	if !isNil(o.Store) {
		toSerialize["store"] = o.Store
	}
	if !isNil(o.Type) {
		toSerialize["type"] = o.Type
	}

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return json.Marshal(toSerialize)
}

func (o *KeystoreDTO) UnmarshalJSON(bytes []byte) (err error) {
	varKeystoreDTO := _KeystoreDTO{}

	if err = json.Unmarshal(bytes, &varKeystoreDTO); err == nil {
		*o = KeystoreDTO(varKeystoreDTO)
	}

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(bytes, &additionalProperties); err == nil {
		delete(additionalProperties, "certificateAlias")
		delete(additionalProperties, "displayName")
		delete(additionalProperties, "elementId")
		delete(additionalProperties, "id")
		delete(additionalProperties, "keystorePassOnly")
		delete(additionalProperties, "name")
		delete(additionalProperties, "password")
		delete(additionalProperties, "privateKeyName")
		delete(additionalProperties, "privateKeyPassword")
		delete(additionalProperties, "store")
		delete(additionalProperties, "type")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableKeystoreDTO struct {
	value *KeystoreDTO
	isSet bool
}

func (v NullableKeystoreDTO) Get() *KeystoreDTO {
	return v.value
}

func (v *NullableKeystoreDTO) Set(val *KeystoreDTO) {
	v.value = val
	v.isSet = true
}

func (v NullableKeystoreDTO) IsSet() bool {
	return v.isSet
}

func (v *NullableKeystoreDTO) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableKeystoreDTO(val *KeystoreDTO) *NullableKeystoreDTO {
	return &NullableKeystoreDTO{value: val, isSet: true}
}

func (v NullableKeystoreDTO) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableKeystoreDTO) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


