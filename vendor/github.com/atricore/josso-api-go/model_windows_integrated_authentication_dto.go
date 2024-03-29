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

// WindowsIntegratedAuthenticationDTO struct for WindowsIntegratedAuthenticationDTO
type WindowsIntegratedAuthenticationDTO struct {
	DelegatedAuthentications []DelegatedAuthenticationDTO `json:"delegatedAuthentications,omitempty"`
	Description *string `json:"description,omitempty"`
	DisplayName *string `json:"displayName,omitempty"`
	Domain *string `json:"domain,omitempty"`
	DomainController *string `json:"domainController,omitempty"`
	ElementId *string `json:"elementId,omitempty"`
	Host *string `json:"host,omitempty"`
	Id *int64 `json:"id,omitempty"`
	KeyTab *ResourceDTO `json:"keyTab,omitempty"`
	Name *string `json:"name,omitempty"`
	OverwriteKerberosSetup *bool `json:"overwriteKerberosSetup,omitempty"`
	Port *int32 `json:"port,omitempty"`
	Protocol *string `json:"protocol,omitempty"`
	ServiceClass *string `json:"serviceClass,omitempty"`
	ServiceName *string `json:"serviceName,omitempty"`
	X *float64 `json:"x,omitempty"`
	Y *float64 `json:"y,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _WindowsIntegratedAuthenticationDTO WindowsIntegratedAuthenticationDTO

// NewWindowsIntegratedAuthenticationDTO instantiates a new WindowsIntegratedAuthenticationDTO object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewWindowsIntegratedAuthenticationDTO() *WindowsIntegratedAuthenticationDTO {
	this := WindowsIntegratedAuthenticationDTO{}
	return &this
}

// NewWindowsIntegratedAuthenticationDTOWithDefaults instantiates a new WindowsIntegratedAuthenticationDTO object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewWindowsIntegratedAuthenticationDTOWithDefaults() *WindowsIntegratedAuthenticationDTO {
	this := WindowsIntegratedAuthenticationDTO{}
	return &this
}

// GetDelegatedAuthentications returns the DelegatedAuthentications field value if set, zero value otherwise.
func (o *WindowsIntegratedAuthenticationDTO) GetDelegatedAuthentications() []DelegatedAuthenticationDTO {
	if o == nil || o.DelegatedAuthentications == nil {
		var ret []DelegatedAuthenticationDTO
		return ret
	}
	return o.DelegatedAuthentications
}

// GetDelegatedAuthenticationsOk returns a tuple with the DelegatedAuthentications field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WindowsIntegratedAuthenticationDTO) GetDelegatedAuthenticationsOk() ([]DelegatedAuthenticationDTO, bool) {
	if o == nil || o.DelegatedAuthentications == nil {
		return nil, false
	}
	return o.DelegatedAuthentications, true
}

// HasDelegatedAuthentications returns a boolean if a field has been set.
func (o *WindowsIntegratedAuthenticationDTO) HasDelegatedAuthentications() bool {
	if o != nil && o.DelegatedAuthentications != nil {
		return true
	}

	return false
}

// SetDelegatedAuthentications gets a reference to the given []DelegatedAuthenticationDTO and assigns it to the DelegatedAuthentications field.
func (o *WindowsIntegratedAuthenticationDTO) SetDelegatedAuthentications(v []DelegatedAuthenticationDTO) {
	o.DelegatedAuthentications = v
}

// GetDescription returns the Description field value if set, zero value otherwise.
func (o *WindowsIntegratedAuthenticationDTO) GetDescription() string {
	if o == nil || o.Description == nil {
		var ret string
		return ret
	}
	return *o.Description
}

// GetDescriptionOk returns a tuple with the Description field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WindowsIntegratedAuthenticationDTO) GetDescriptionOk() (*string, bool) {
	if o == nil || o.Description == nil {
		return nil, false
	}
	return o.Description, true
}

// HasDescription returns a boolean if a field has been set.
func (o *WindowsIntegratedAuthenticationDTO) HasDescription() bool {
	if o != nil && o.Description != nil {
		return true
	}

	return false
}

// SetDescription gets a reference to the given string and assigns it to the Description field.
func (o *WindowsIntegratedAuthenticationDTO) SetDescription(v string) {
	o.Description = &v
}

// GetDisplayName returns the DisplayName field value if set, zero value otherwise.
func (o *WindowsIntegratedAuthenticationDTO) GetDisplayName() string {
	if o == nil || o.DisplayName == nil {
		var ret string
		return ret
	}
	return *o.DisplayName
}

// GetDisplayNameOk returns a tuple with the DisplayName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WindowsIntegratedAuthenticationDTO) GetDisplayNameOk() (*string, bool) {
	if o == nil || o.DisplayName == nil {
		return nil, false
	}
	return o.DisplayName, true
}

// HasDisplayName returns a boolean if a field has been set.
func (o *WindowsIntegratedAuthenticationDTO) HasDisplayName() bool {
	if o != nil && o.DisplayName != nil {
		return true
	}

	return false
}

// SetDisplayName gets a reference to the given string and assigns it to the DisplayName field.
func (o *WindowsIntegratedAuthenticationDTO) SetDisplayName(v string) {
	o.DisplayName = &v
}

// GetDomain returns the Domain field value if set, zero value otherwise.
func (o *WindowsIntegratedAuthenticationDTO) GetDomain() string {
	if o == nil || o.Domain == nil {
		var ret string
		return ret
	}
	return *o.Domain
}

// GetDomainOk returns a tuple with the Domain field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WindowsIntegratedAuthenticationDTO) GetDomainOk() (*string, bool) {
	if o == nil || o.Domain == nil {
		return nil, false
	}
	return o.Domain, true
}

// HasDomain returns a boolean if a field has been set.
func (o *WindowsIntegratedAuthenticationDTO) HasDomain() bool {
	if o != nil && o.Domain != nil {
		return true
	}

	return false
}

// SetDomain gets a reference to the given string and assigns it to the Domain field.
func (o *WindowsIntegratedAuthenticationDTO) SetDomain(v string) {
	o.Domain = &v
}

// GetDomainController returns the DomainController field value if set, zero value otherwise.
func (o *WindowsIntegratedAuthenticationDTO) GetDomainController() string {
	if o == nil || o.DomainController == nil {
		var ret string
		return ret
	}
	return *o.DomainController
}

// GetDomainControllerOk returns a tuple with the DomainController field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WindowsIntegratedAuthenticationDTO) GetDomainControllerOk() (*string, bool) {
	if o == nil || o.DomainController == nil {
		return nil, false
	}
	return o.DomainController, true
}

// HasDomainController returns a boolean if a field has been set.
func (o *WindowsIntegratedAuthenticationDTO) HasDomainController() bool {
	if o != nil && o.DomainController != nil {
		return true
	}

	return false
}

// SetDomainController gets a reference to the given string and assigns it to the DomainController field.
func (o *WindowsIntegratedAuthenticationDTO) SetDomainController(v string) {
	o.DomainController = &v
}

// GetElementId returns the ElementId field value if set, zero value otherwise.
func (o *WindowsIntegratedAuthenticationDTO) GetElementId() string {
	if o == nil || o.ElementId == nil {
		var ret string
		return ret
	}
	return *o.ElementId
}

// GetElementIdOk returns a tuple with the ElementId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WindowsIntegratedAuthenticationDTO) GetElementIdOk() (*string, bool) {
	if o == nil || o.ElementId == nil {
		return nil, false
	}
	return o.ElementId, true
}

// HasElementId returns a boolean if a field has been set.
func (o *WindowsIntegratedAuthenticationDTO) HasElementId() bool {
	if o != nil && o.ElementId != nil {
		return true
	}

	return false
}

// SetElementId gets a reference to the given string and assigns it to the ElementId field.
func (o *WindowsIntegratedAuthenticationDTO) SetElementId(v string) {
	o.ElementId = &v
}

// GetHost returns the Host field value if set, zero value otherwise.
func (o *WindowsIntegratedAuthenticationDTO) GetHost() string {
	if o == nil || o.Host == nil {
		var ret string
		return ret
	}
	return *o.Host
}

// GetHostOk returns a tuple with the Host field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WindowsIntegratedAuthenticationDTO) GetHostOk() (*string, bool) {
	if o == nil || o.Host == nil {
		return nil, false
	}
	return o.Host, true
}

// HasHost returns a boolean if a field has been set.
func (o *WindowsIntegratedAuthenticationDTO) HasHost() bool {
	if o != nil && o.Host != nil {
		return true
	}

	return false
}

// SetHost gets a reference to the given string and assigns it to the Host field.
func (o *WindowsIntegratedAuthenticationDTO) SetHost(v string) {
	o.Host = &v
}

// GetId returns the Id field value if set, zero value otherwise.
func (o *WindowsIntegratedAuthenticationDTO) GetId() int64 {
	if o == nil || o.Id == nil {
		var ret int64
		return ret
	}
	return *o.Id
}

// GetIdOk returns a tuple with the Id field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WindowsIntegratedAuthenticationDTO) GetIdOk() (*int64, bool) {
	if o == nil || o.Id == nil {
		return nil, false
	}
	return o.Id, true
}

// HasId returns a boolean if a field has been set.
func (o *WindowsIntegratedAuthenticationDTO) HasId() bool {
	if o != nil && o.Id != nil {
		return true
	}

	return false
}

// SetId gets a reference to the given int64 and assigns it to the Id field.
func (o *WindowsIntegratedAuthenticationDTO) SetId(v int64) {
	o.Id = &v
}

// GetKeyTab returns the KeyTab field value if set, zero value otherwise.
func (o *WindowsIntegratedAuthenticationDTO) GetKeyTab() ResourceDTO {
	if o == nil || o.KeyTab == nil {
		var ret ResourceDTO
		return ret
	}
	return *o.KeyTab
}

// GetKeyTabOk returns a tuple with the KeyTab field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WindowsIntegratedAuthenticationDTO) GetKeyTabOk() (*ResourceDTO, bool) {
	if o == nil || o.KeyTab == nil {
		return nil, false
	}
	return o.KeyTab, true
}

// HasKeyTab returns a boolean if a field has been set.
func (o *WindowsIntegratedAuthenticationDTO) HasKeyTab() bool {
	if o != nil && o.KeyTab != nil {
		return true
	}

	return false
}

// SetKeyTab gets a reference to the given ResourceDTO and assigns it to the KeyTab field.
func (o *WindowsIntegratedAuthenticationDTO) SetKeyTab(v ResourceDTO) {
	o.KeyTab = &v
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *WindowsIntegratedAuthenticationDTO) GetName() string {
	if o == nil || o.Name == nil {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WindowsIntegratedAuthenticationDTO) GetNameOk() (*string, bool) {
	if o == nil || o.Name == nil {
		return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *WindowsIntegratedAuthenticationDTO) HasName() bool {
	if o != nil && o.Name != nil {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *WindowsIntegratedAuthenticationDTO) SetName(v string) {
	o.Name = &v
}

// GetOverwriteKerberosSetup returns the OverwriteKerberosSetup field value if set, zero value otherwise.
func (o *WindowsIntegratedAuthenticationDTO) GetOverwriteKerberosSetup() bool {
	if o == nil || o.OverwriteKerberosSetup == nil {
		var ret bool
		return ret
	}
	return *o.OverwriteKerberosSetup
}

// GetOverwriteKerberosSetupOk returns a tuple with the OverwriteKerberosSetup field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WindowsIntegratedAuthenticationDTO) GetOverwriteKerberosSetupOk() (*bool, bool) {
	if o == nil || o.OverwriteKerberosSetup == nil {
		return nil, false
	}
	return o.OverwriteKerberosSetup, true
}

// HasOverwriteKerberosSetup returns a boolean if a field has been set.
func (o *WindowsIntegratedAuthenticationDTO) HasOverwriteKerberosSetup() bool {
	if o != nil && o.OverwriteKerberosSetup != nil {
		return true
	}

	return false
}

// SetOverwriteKerberosSetup gets a reference to the given bool and assigns it to the OverwriteKerberosSetup field.
func (o *WindowsIntegratedAuthenticationDTO) SetOverwriteKerberosSetup(v bool) {
	o.OverwriteKerberosSetup = &v
}

// GetPort returns the Port field value if set, zero value otherwise.
func (o *WindowsIntegratedAuthenticationDTO) GetPort() int32 {
	if o == nil || o.Port == nil {
		var ret int32
		return ret
	}
	return *o.Port
}

// GetPortOk returns a tuple with the Port field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WindowsIntegratedAuthenticationDTO) GetPortOk() (*int32, bool) {
	if o == nil || o.Port == nil {
		return nil, false
	}
	return o.Port, true
}

// HasPort returns a boolean if a field has been set.
func (o *WindowsIntegratedAuthenticationDTO) HasPort() bool {
	if o != nil && o.Port != nil {
		return true
	}

	return false
}

// SetPort gets a reference to the given int32 and assigns it to the Port field.
func (o *WindowsIntegratedAuthenticationDTO) SetPort(v int32) {
	o.Port = &v
}

// GetProtocol returns the Protocol field value if set, zero value otherwise.
func (o *WindowsIntegratedAuthenticationDTO) GetProtocol() string {
	if o == nil || o.Protocol == nil {
		var ret string
		return ret
	}
	return *o.Protocol
}

// GetProtocolOk returns a tuple with the Protocol field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WindowsIntegratedAuthenticationDTO) GetProtocolOk() (*string, bool) {
	if o == nil || o.Protocol == nil {
		return nil, false
	}
	return o.Protocol, true
}

// HasProtocol returns a boolean if a field has been set.
func (o *WindowsIntegratedAuthenticationDTO) HasProtocol() bool {
	if o != nil && o.Protocol != nil {
		return true
	}

	return false
}

// SetProtocol gets a reference to the given string and assigns it to the Protocol field.
func (o *WindowsIntegratedAuthenticationDTO) SetProtocol(v string) {
	o.Protocol = &v
}

// GetServiceClass returns the ServiceClass field value if set, zero value otherwise.
func (o *WindowsIntegratedAuthenticationDTO) GetServiceClass() string {
	if o == nil || o.ServiceClass == nil {
		var ret string
		return ret
	}
	return *o.ServiceClass
}

// GetServiceClassOk returns a tuple with the ServiceClass field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WindowsIntegratedAuthenticationDTO) GetServiceClassOk() (*string, bool) {
	if o == nil || o.ServiceClass == nil {
		return nil, false
	}
	return o.ServiceClass, true
}

// HasServiceClass returns a boolean if a field has been set.
func (o *WindowsIntegratedAuthenticationDTO) HasServiceClass() bool {
	if o != nil && o.ServiceClass != nil {
		return true
	}

	return false
}

// SetServiceClass gets a reference to the given string and assigns it to the ServiceClass field.
func (o *WindowsIntegratedAuthenticationDTO) SetServiceClass(v string) {
	o.ServiceClass = &v
}

// GetServiceName returns the ServiceName field value if set, zero value otherwise.
func (o *WindowsIntegratedAuthenticationDTO) GetServiceName() string {
	if o == nil || o.ServiceName == nil {
		var ret string
		return ret
	}
	return *o.ServiceName
}

// GetServiceNameOk returns a tuple with the ServiceName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WindowsIntegratedAuthenticationDTO) GetServiceNameOk() (*string, bool) {
	if o == nil || o.ServiceName == nil {
		return nil, false
	}
	return o.ServiceName, true
}

// HasServiceName returns a boolean if a field has been set.
func (o *WindowsIntegratedAuthenticationDTO) HasServiceName() bool {
	if o != nil && o.ServiceName != nil {
		return true
	}

	return false
}

// SetServiceName gets a reference to the given string and assigns it to the ServiceName field.
func (o *WindowsIntegratedAuthenticationDTO) SetServiceName(v string) {
	o.ServiceName = &v
}

// GetX returns the X field value if set, zero value otherwise.
func (o *WindowsIntegratedAuthenticationDTO) GetX() float64 {
	if o == nil || o.X == nil {
		var ret float64
		return ret
	}
	return *o.X
}

// GetXOk returns a tuple with the X field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WindowsIntegratedAuthenticationDTO) GetXOk() (*float64, bool) {
	if o == nil || o.X == nil {
		return nil, false
	}
	return o.X, true
}

// HasX returns a boolean if a field has been set.
func (o *WindowsIntegratedAuthenticationDTO) HasX() bool {
	if o != nil && o.X != nil {
		return true
	}

	return false
}

// SetX gets a reference to the given float64 and assigns it to the X field.
func (o *WindowsIntegratedAuthenticationDTO) SetX(v float64) {
	o.X = &v
}

// GetY returns the Y field value if set, zero value otherwise.
func (o *WindowsIntegratedAuthenticationDTO) GetY() float64 {
	if o == nil || o.Y == nil {
		var ret float64
		return ret
	}
	return *o.Y
}

// GetYOk returns a tuple with the Y field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WindowsIntegratedAuthenticationDTO) GetYOk() (*float64, bool) {
	if o == nil || o.Y == nil {
		return nil, false
	}
	return o.Y, true
}

// HasY returns a boolean if a field has been set.
func (o *WindowsIntegratedAuthenticationDTO) HasY() bool {
	if o != nil && o.Y != nil {
		return true
	}

	return false
}

// SetY gets a reference to the given float64 and assigns it to the Y field.
func (o *WindowsIntegratedAuthenticationDTO) SetY(v float64) {
	o.Y = &v
}

func (o WindowsIntegratedAuthenticationDTO) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.DelegatedAuthentications != nil {
		toSerialize["delegatedAuthentications"] = o.DelegatedAuthentications
	}
	if o.Description != nil {
		toSerialize["description"] = o.Description
	}
	if o.DisplayName != nil {
		toSerialize["displayName"] = o.DisplayName
	}
	if o.Domain != nil {
		toSerialize["domain"] = o.Domain
	}
	if o.DomainController != nil {
		toSerialize["domainController"] = o.DomainController
	}
	if o.ElementId != nil {
		toSerialize["elementId"] = o.ElementId
	}
	if o.Host != nil {
		toSerialize["host"] = o.Host
	}
	if o.Id != nil {
		toSerialize["id"] = o.Id
	}
	if o.KeyTab != nil {
		toSerialize["keyTab"] = o.KeyTab
	}
	if o.Name != nil {
		toSerialize["name"] = o.Name
	}
	if o.OverwriteKerberosSetup != nil {
		toSerialize["overwriteKerberosSetup"] = o.OverwriteKerberosSetup
	}
	if o.Port != nil {
		toSerialize["port"] = o.Port
	}
	if o.Protocol != nil {
		toSerialize["protocol"] = o.Protocol
	}
	if o.ServiceClass != nil {
		toSerialize["serviceClass"] = o.ServiceClass
	}
	if o.ServiceName != nil {
		toSerialize["serviceName"] = o.ServiceName
	}
	if o.X != nil {
		toSerialize["x"] = o.X
	}
	if o.Y != nil {
		toSerialize["y"] = o.Y
	}

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return json.Marshal(toSerialize)
}

func (o *WindowsIntegratedAuthenticationDTO) UnmarshalJSON(bytes []byte) (err error) {
	varWindowsIntegratedAuthenticationDTO := _WindowsIntegratedAuthenticationDTO{}

	if err = json.Unmarshal(bytes, &varWindowsIntegratedAuthenticationDTO); err == nil {
		*o = WindowsIntegratedAuthenticationDTO(varWindowsIntegratedAuthenticationDTO)
	}

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(bytes, &additionalProperties); err == nil {
		delete(additionalProperties, "delegatedAuthentications")
		delete(additionalProperties, "description")
		delete(additionalProperties, "displayName")
		delete(additionalProperties, "domain")
		delete(additionalProperties, "domainController")
		delete(additionalProperties, "elementId")
		delete(additionalProperties, "host")
		delete(additionalProperties, "id")
		delete(additionalProperties, "keyTab")
		delete(additionalProperties, "name")
		delete(additionalProperties, "overwriteKerberosSetup")
		delete(additionalProperties, "port")
		delete(additionalProperties, "protocol")
		delete(additionalProperties, "serviceClass")
		delete(additionalProperties, "serviceName")
		delete(additionalProperties, "x")
		delete(additionalProperties, "y")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableWindowsIntegratedAuthenticationDTO struct {
	value *WindowsIntegratedAuthenticationDTO
	isSet bool
}

func (v NullableWindowsIntegratedAuthenticationDTO) Get() *WindowsIntegratedAuthenticationDTO {
	return v.value
}

func (v *NullableWindowsIntegratedAuthenticationDTO) Set(val *WindowsIntegratedAuthenticationDTO) {
	v.value = val
	v.isSet = true
}

func (v NullableWindowsIntegratedAuthenticationDTO) IsSet() bool {
	return v.isSet
}

func (v *NullableWindowsIntegratedAuthenticationDTO) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableWindowsIntegratedAuthenticationDTO(val *WindowsIntegratedAuthenticationDTO) *NullableWindowsIntegratedAuthenticationDTO {
	return &NullableWindowsIntegratedAuthenticationDTO{value: val, isSet: true}
}

func (v NullableWindowsIntegratedAuthenticationDTO) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableWindowsIntegratedAuthenticationDTO) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


