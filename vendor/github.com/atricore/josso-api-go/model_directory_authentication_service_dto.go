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

// DirectoryAuthenticationServiceDTO struct for DirectoryAuthenticationServiceDTO
type DirectoryAuthenticationServiceDTO struct {
	CustomClass *CustomClassDTO `json:"customClass,omitempty"`
	DelegatedAuthentications []DelegatedAuthenticationDTO `json:"delegatedAuthentications,omitempty"`
	Description *string `json:"description,omitempty"`
	DisplayName *string `json:"displayName,omitempty"`
	ElementId *string `json:"elementId,omitempty"`
	Id *int64 `json:"id,omitempty"`
	IncludeOperationalAttributes *bool `json:"includeOperationalAttributes,omitempty"`
	InitialContextFactory *string `json:"initialContextFactory,omitempty"`
	LdapSearchScope *string `json:"ldapSearchScope,omitempty"`
	Name *string `json:"name,omitempty"`
	PasswordPolicy *string `json:"passwordPolicy,omitempty"`
	PerformDnSearch *bool `json:"performDnSearch,omitempty"`
	PrincipalUidAttributeID *string `json:"principalUidAttributeID,omitempty"`
	ProviderUrl *string `json:"providerUrl,omitempty"`
	Referrals *string `json:"referrals,omitempty"`
	SecurityAuthentication *string `json:"securityAuthentication,omitempty"`
	SecurityCredential *string `json:"securityCredential,omitempty"`
	SecurityPrincipal *string `json:"securityPrincipal,omitempty"`
	SimpleAuthnSaml2AuthnCtxClass *string `json:"simpleAuthnSaml2AuthnCtxClass,omitempty"`
	UsersCtxDN *string `json:"usersCtxDN,omitempty"`
	X *float64 `json:"x,omitempty"`
	Y *float64 `json:"y,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _DirectoryAuthenticationServiceDTO DirectoryAuthenticationServiceDTO

// NewDirectoryAuthenticationServiceDTO instantiates a new DirectoryAuthenticationServiceDTO object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewDirectoryAuthenticationServiceDTO() *DirectoryAuthenticationServiceDTO {
	this := DirectoryAuthenticationServiceDTO{}
	return &this
}

// NewDirectoryAuthenticationServiceDTOWithDefaults instantiates a new DirectoryAuthenticationServiceDTO object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewDirectoryAuthenticationServiceDTOWithDefaults() *DirectoryAuthenticationServiceDTO {
	this := DirectoryAuthenticationServiceDTO{}
	return &this
}

// GetCustomClass returns the CustomClass field value if set, zero value otherwise.
func (o *DirectoryAuthenticationServiceDTO) GetCustomClass() CustomClassDTO {
	if o == nil || isNil(o.CustomClass) {
		var ret CustomClassDTO
		return ret
	}
	return *o.CustomClass
}

// GetCustomClassOk returns a tuple with the CustomClass field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DirectoryAuthenticationServiceDTO) GetCustomClassOk() (*CustomClassDTO, bool) {
	if o == nil || isNil(o.CustomClass) {
    return nil, false
	}
	return o.CustomClass, true
}

// HasCustomClass returns a boolean if a field has been set.
func (o *DirectoryAuthenticationServiceDTO) HasCustomClass() bool {
	if o != nil && !isNil(o.CustomClass) {
		return true
	}

	return false
}

// SetCustomClass gets a reference to the given CustomClassDTO and assigns it to the CustomClass field.
func (o *DirectoryAuthenticationServiceDTO) SetCustomClass(v CustomClassDTO) {
	o.CustomClass = &v
}

// GetDelegatedAuthentications returns the DelegatedAuthentications field value if set, zero value otherwise.
func (o *DirectoryAuthenticationServiceDTO) GetDelegatedAuthentications() []DelegatedAuthenticationDTO {
	if o == nil || isNil(o.DelegatedAuthentications) {
		var ret []DelegatedAuthenticationDTO
		return ret
	}
	return o.DelegatedAuthentications
}

// GetDelegatedAuthenticationsOk returns a tuple with the DelegatedAuthentications field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DirectoryAuthenticationServiceDTO) GetDelegatedAuthenticationsOk() ([]DelegatedAuthenticationDTO, bool) {
	if o == nil || isNil(o.DelegatedAuthentications) {
    return nil, false
	}
	return o.DelegatedAuthentications, true
}

// HasDelegatedAuthentications returns a boolean if a field has been set.
func (o *DirectoryAuthenticationServiceDTO) HasDelegatedAuthentications() bool {
	if o != nil && !isNil(o.DelegatedAuthentications) {
		return true
	}

	return false
}

// SetDelegatedAuthentications gets a reference to the given []DelegatedAuthenticationDTO and assigns it to the DelegatedAuthentications field.
func (o *DirectoryAuthenticationServiceDTO) SetDelegatedAuthentications(v []DelegatedAuthenticationDTO) {
	o.DelegatedAuthentications = v
}

// GetDescription returns the Description field value if set, zero value otherwise.
func (o *DirectoryAuthenticationServiceDTO) GetDescription() string {
	if o == nil || isNil(o.Description) {
		var ret string
		return ret
	}
	return *o.Description
}

// GetDescriptionOk returns a tuple with the Description field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DirectoryAuthenticationServiceDTO) GetDescriptionOk() (*string, bool) {
	if o == nil || isNil(o.Description) {
    return nil, false
	}
	return o.Description, true
}

// HasDescription returns a boolean if a field has been set.
func (o *DirectoryAuthenticationServiceDTO) HasDescription() bool {
	if o != nil && !isNil(o.Description) {
		return true
	}

	return false
}

// SetDescription gets a reference to the given string and assigns it to the Description field.
func (o *DirectoryAuthenticationServiceDTO) SetDescription(v string) {
	o.Description = &v
}

// GetDisplayName returns the DisplayName field value if set, zero value otherwise.
func (o *DirectoryAuthenticationServiceDTO) GetDisplayName() string {
	if o == nil || isNil(o.DisplayName) {
		var ret string
		return ret
	}
	return *o.DisplayName
}

// GetDisplayNameOk returns a tuple with the DisplayName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DirectoryAuthenticationServiceDTO) GetDisplayNameOk() (*string, bool) {
	if o == nil || isNil(o.DisplayName) {
    return nil, false
	}
	return o.DisplayName, true
}

// HasDisplayName returns a boolean if a field has been set.
func (o *DirectoryAuthenticationServiceDTO) HasDisplayName() bool {
	if o != nil && !isNil(o.DisplayName) {
		return true
	}

	return false
}

// SetDisplayName gets a reference to the given string and assigns it to the DisplayName field.
func (o *DirectoryAuthenticationServiceDTO) SetDisplayName(v string) {
	o.DisplayName = &v
}

// GetElementId returns the ElementId field value if set, zero value otherwise.
func (o *DirectoryAuthenticationServiceDTO) GetElementId() string {
	if o == nil || isNil(o.ElementId) {
		var ret string
		return ret
	}
	return *o.ElementId
}

// GetElementIdOk returns a tuple with the ElementId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DirectoryAuthenticationServiceDTO) GetElementIdOk() (*string, bool) {
	if o == nil || isNil(o.ElementId) {
    return nil, false
	}
	return o.ElementId, true
}

// HasElementId returns a boolean if a field has been set.
func (o *DirectoryAuthenticationServiceDTO) HasElementId() bool {
	if o != nil && !isNil(o.ElementId) {
		return true
	}

	return false
}

// SetElementId gets a reference to the given string and assigns it to the ElementId field.
func (o *DirectoryAuthenticationServiceDTO) SetElementId(v string) {
	o.ElementId = &v
}

// GetId returns the Id field value if set, zero value otherwise.
func (o *DirectoryAuthenticationServiceDTO) GetId() int64 {
	if o == nil || isNil(o.Id) {
		var ret int64
		return ret
	}
	return *o.Id
}

// GetIdOk returns a tuple with the Id field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DirectoryAuthenticationServiceDTO) GetIdOk() (*int64, bool) {
	if o == nil || isNil(o.Id) {
    return nil, false
	}
	return o.Id, true
}

// HasId returns a boolean if a field has been set.
func (o *DirectoryAuthenticationServiceDTO) HasId() bool {
	if o != nil && !isNil(o.Id) {
		return true
	}

	return false
}

// SetId gets a reference to the given int64 and assigns it to the Id field.
func (o *DirectoryAuthenticationServiceDTO) SetId(v int64) {
	o.Id = &v
}

// GetIncludeOperationalAttributes returns the IncludeOperationalAttributes field value if set, zero value otherwise.
func (o *DirectoryAuthenticationServiceDTO) GetIncludeOperationalAttributes() bool {
	if o == nil || isNil(o.IncludeOperationalAttributes) {
		var ret bool
		return ret
	}
	return *o.IncludeOperationalAttributes
}

// GetIncludeOperationalAttributesOk returns a tuple with the IncludeOperationalAttributes field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DirectoryAuthenticationServiceDTO) GetIncludeOperationalAttributesOk() (*bool, bool) {
	if o == nil || isNil(o.IncludeOperationalAttributes) {
    return nil, false
	}
	return o.IncludeOperationalAttributes, true
}

// HasIncludeOperationalAttributes returns a boolean if a field has been set.
func (o *DirectoryAuthenticationServiceDTO) HasIncludeOperationalAttributes() bool {
	if o != nil && !isNil(o.IncludeOperationalAttributes) {
		return true
	}

	return false
}

// SetIncludeOperationalAttributes gets a reference to the given bool and assigns it to the IncludeOperationalAttributes field.
func (o *DirectoryAuthenticationServiceDTO) SetIncludeOperationalAttributes(v bool) {
	o.IncludeOperationalAttributes = &v
}

// GetInitialContextFactory returns the InitialContextFactory field value if set, zero value otherwise.
func (o *DirectoryAuthenticationServiceDTO) GetInitialContextFactory() string {
	if o == nil || isNil(o.InitialContextFactory) {
		var ret string
		return ret
	}
	return *o.InitialContextFactory
}

// GetInitialContextFactoryOk returns a tuple with the InitialContextFactory field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DirectoryAuthenticationServiceDTO) GetInitialContextFactoryOk() (*string, bool) {
	if o == nil || isNil(o.InitialContextFactory) {
    return nil, false
	}
	return o.InitialContextFactory, true
}

// HasInitialContextFactory returns a boolean if a field has been set.
func (o *DirectoryAuthenticationServiceDTO) HasInitialContextFactory() bool {
	if o != nil && !isNil(o.InitialContextFactory) {
		return true
	}

	return false
}

// SetInitialContextFactory gets a reference to the given string and assigns it to the InitialContextFactory field.
func (o *DirectoryAuthenticationServiceDTO) SetInitialContextFactory(v string) {
	o.InitialContextFactory = &v
}

// GetLdapSearchScope returns the LdapSearchScope field value if set, zero value otherwise.
func (o *DirectoryAuthenticationServiceDTO) GetLdapSearchScope() string {
	if o == nil || isNil(o.LdapSearchScope) {
		var ret string
		return ret
	}
	return *o.LdapSearchScope
}

// GetLdapSearchScopeOk returns a tuple with the LdapSearchScope field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DirectoryAuthenticationServiceDTO) GetLdapSearchScopeOk() (*string, bool) {
	if o == nil || isNil(o.LdapSearchScope) {
    return nil, false
	}
	return o.LdapSearchScope, true
}

// HasLdapSearchScope returns a boolean if a field has been set.
func (o *DirectoryAuthenticationServiceDTO) HasLdapSearchScope() bool {
	if o != nil && !isNil(o.LdapSearchScope) {
		return true
	}

	return false
}

// SetLdapSearchScope gets a reference to the given string and assigns it to the LdapSearchScope field.
func (o *DirectoryAuthenticationServiceDTO) SetLdapSearchScope(v string) {
	o.LdapSearchScope = &v
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *DirectoryAuthenticationServiceDTO) GetName() string {
	if o == nil || isNil(o.Name) {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DirectoryAuthenticationServiceDTO) GetNameOk() (*string, bool) {
	if o == nil || isNil(o.Name) {
    return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *DirectoryAuthenticationServiceDTO) HasName() bool {
	if o != nil && !isNil(o.Name) {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *DirectoryAuthenticationServiceDTO) SetName(v string) {
	o.Name = &v
}

// GetPasswordPolicy returns the PasswordPolicy field value if set, zero value otherwise.
func (o *DirectoryAuthenticationServiceDTO) GetPasswordPolicy() string {
	if o == nil || isNil(o.PasswordPolicy) {
		var ret string
		return ret
	}
	return *o.PasswordPolicy
}

// GetPasswordPolicyOk returns a tuple with the PasswordPolicy field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DirectoryAuthenticationServiceDTO) GetPasswordPolicyOk() (*string, bool) {
	if o == nil || isNil(o.PasswordPolicy) {
    return nil, false
	}
	return o.PasswordPolicy, true
}

// HasPasswordPolicy returns a boolean if a field has been set.
func (o *DirectoryAuthenticationServiceDTO) HasPasswordPolicy() bool {
	if o != nil && !isNil(o.PasswordPolicy) {
		return true
	}

	return false
}

// SetPasswordPolicy gets a reference to the given string and assigns it to the PasswordPolicy field.
func (o *DirectoryAuthenticationServiceDTO) SetPasswordPolicy(v string) {
	o.PasswordPolicy = &v
}

// GetPerformDnSearch returns the PerformDnSearch field value if set, zero value otherwise.
func (o *DirectoryAuthenticationServiceDTO) GetPerformDnSearch() bool {
	if o == nil || isNil(o.PerformDnSearch) {
		var ret bool
		return ret
	}
	return *o.PerformDnSearch
}

// GetPerformDnSearchOk returns a tuple with the PerformDnSearch field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DirectoryAuthenticationServiceDTO) GetPerformDnSearchOk() (*bool, bool) {
	if o == nil || isNil(o.PerformDnSearch) {
    return nil, false
	}
	return o.PerformDnSearch, true
}

// HasPerformDnSearch returns a boolean if a field has been set.
func (o *DirectoryAuthenticationServiceDTO) HasPerformDnSearch() bool {
	if o != nil && !isNil(o.PerformDnSearch) {
		return true
	}

	return false
}

// SetPerformDnSearch gets a reference to the given bool and assigns it to the PerformDnSearch field.
func (o *DirectoryAuthenticationServiceDTO) SetPerformDnSearch(v bool) {
	o.PerformDnSearch = &v
}

// GetPrincipalUidAttributeID returns the PrincipalUidAttributeID field value if set, zero value otherwise.
func (o *DirectoryAuthenticationServiceDTO) GetPrincipalUidAttributeID() string {
	if o == nil || isNil(o.PrincipalUidAttributeID) {
		var ret string
		return ret
	}
	return *o.PrincipalUidAttributeID
}

// GetPrincipalUidAttributeIDOk returns a tuple with the PrincipalUidAttributeID field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DirectoryAuthenticationServiceDTO) GetPrincipalUidAttributeIDOk() (*string, bool) {
	if o == nil || isNil(o.PrincipalUidAttributeID) {
    return nil, false
	}
	return o.PrincipalUidAttributeID, true
}

// HasPrincipalUidAttributeID returns a boolean if a field has been set.
func (o *DirectoryAuthenticationServiceDTO) HasPrincipalUidAttributeID() bool {
	if o != nil && !isNil(o.PrincipalUidAttributeID) {
		return true
	}

	return false
}

// SetPrincipalUidAttributeID gets a reference to the given string and assigns it to the PrincipalUidAttributeID field.
func (o *DirectoryAuthenticationServiceDTO) SetPrincipalUidAttributeID(v string) {
	o.PrincipalUidAttributeID = &v
}

// GetProviderUrl returns the ProviderUrl field value if set, zero value otherwise.
func (o *DirectoryAuthenticationServiceDTO) GetProviderUrl() string {
	if o == nil || isNil(o.ProviderUrl) {
		var ret string
		return ret
	}
	return *o.ProviderUrl
}

// GetProviderUrlOk returns a tuple with the ProviderUrl field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DirectoryAuthenticationServiceDTO) GetProviderUrlOk() (*string, bool) {
	if o == nil || isNil(o.ProviderUrl) {
    return nil, false
	}
	return o.ProviderUrl, true
}

// HasProviderUrl returns a boolean if a field has been set.
func (o *DirectoryAuthenticationServiceDTO) HasProviderUrl() bool {
	if o != nil && !isNil(o.ProviderUrl) {
		return true
	}

	return false
}

// SetProviderUrl gets a reference to the given string and assigns it to the ProviderUrl field.
func (o *DirectoryAuthenticationServiceDTO) SetProviderUrl(v string) {
	o.ProviderUrl = &v
}

// GetReferrals returns the Referrals field value if set, zero value otherwise.
func (o *DirectoryAuthenticationServiceDTO) GetReferrals() string {
	if o == nil || isNil(o.Referrals) {
		var ret string
		return ret
	}
	return *o.Referrals
}

// GetReferralsOk returns a tuple with the Referrals field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DirectoryAuthenticationServiceDTO) GetReferralsOk() (*string, bool) {
	if o == nil || isNil(o.Referrals) {
    return nil, false
	}
	return o.Referrals, true
}

// HasReferrals returns a boolean if a field has been set.
func (o *DirectoryAuthenticationServiceDTO) HasReferrals() bool {
	if o != nil && !isNil(o.Referrals) {
		return true
	}

	return false
}

// SetReferrals gets a reference to the given string and assigns it to the Referrals field.
func (o *DirectoryAuthenticationServiceDTO) SetReferrals(v string) {
	o.Referrals = &v
}

// GetSecurityAuthentication returns the SecurityAuthentication field value if set, zero value otherwise.
func (o *DirectoryAuthenticationServiceDTO) GetSecurityAuthentication() string {
	if o == nil || isNil(o.SecurityAuthentication) {
		var ret string
		return ret
	}
	return *o.SecurityAuthentication
}

// GetSecurityAuthenticationOk returns a tuple with the SecurityAuthentication field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DirectoryAuthenticationServiceDTO) GetSecurityAuthenticationOk() (*string, bool) {
	if o == nil || isNil(o.SecurityAuthentication) {
    return nil, false
	}
	return o.SecurityAuthentication, true
}

// HasSecurityAuthentication returns a boolean if a field has been set.
func (o *DirectoryAuthenticationServiceDTO) HasSecurityAuthentication() bool {
	if o != nil && !isNil(o.SecurityAuthentication) {
		return true
	}

	return false
}

// SetSecurityAuthentication gets a reference to the given string and assigns it to the SecurityAuthentication field.
func (o *DirectoryAuthenticationServiceDTO) SetSecurityAuthentication(v string) {
	o.SecurityAuthentication = &v
}

// GetSecurityCredential returns the SecurityCredential field value if set, zero value otherwise.
func (o *DirectoryAuthenticationServiceDTO) GetSecurityCredential() string {
	if o == nil || isNil(o.SecurityCredential) {
		var ret string
		return ret
	}
	return *o.SecurityCredential
}

// GetSecurityCredentialOk returns a tuple with the SecurityCredential field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DirectoryAuthenticationServiceDTO) GetSecurityCredentialOk() (*string, bool) {
	if o == nil || isNil(o.SecurityCredential) {
    return nil, false
	}
	return o.SecurityCredential, true
}

// HasSecurityCredential returns a boolean if a field has been set.
func (o *DirectoryAuthenticationServiceDTO) HasSecurityCredential() bool {
	if o != nil && !isNil(o.SecurityCredential) {
		return true
	}

	return false
}

// SetSecurityCredential gets a reference to the given string and assigns it to the SecurityCredential field.
func (o *DirectoryAuthenticationServiceDTO) SetSecurityCredential(v string) {
	o.SecurityCredential = &v
}

// GetSecurityPrincipal returns the SecurityPrincipal field value if set, zero value otherwise.
func (o *DirectoryAuthenticationServiceDTO) GetSecurityPrincipal() string {
	if o == nil || isNil(o.SecurityPrincipal) {
		var ret string
		return ret
	}
	return *o.SecurityPrincipal
}

// GetSecurityPrincipalOk returns a tuple with the SecurityPrincipal field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DirectoryAuthenticationServiceDTO) GetSecurityPrincipalOk() (*string, bool) {
	if o == nil || isNil(o.SecurityPrincipal) {
    return nil, false
	}
	return o.SecurityPrincipal, true
}

// HasSecurityPrincipal returns a boolean if a field has been set.
func (o *DirectoryAuthenticationServiceDTO) HasSecurityPrincipal() bool {
	if o != nil && !isNil(o.SecurityPrincipal) {
		return true
	}

	return false
}

// SetSecurityPrincipal gets a reference to the given string and assigns it to the SecurityPrincipal field.
func (o *DirectoryAuthenticationServiceDTO) SetSecurityPrincipal(v string) {
	o.SecurityPrincipal = &v
}

// GetSimpleAuthnSaml2AuthnCtxClass returns the SimpleAuthnSaml2AuthnCtxClass field value if set, zero value otherwise.
func (o *DirectoryAuthenticationServiceDTO) GetSimpleAuthnSaml2AuthnCtxClass() string {
	if o == nil || isNil(o.SimpleAuthnSaml2AuthnCtxClass) {
		var ret string
		return ret
	}
	return *o.SimpleAuthnSaml2AuthnCtxClass
}

// GetSimpleAuthnSaml2AuthnCtxClassOk returns a tuple with the SimpleAuthnSaml2AuthnCtxClass field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DirectoryAuthenticationServiceDTO) GetSimpleAuthnSaml2AuthnCtxClassOk() (*string, bool) {
	if o == nil || isNil(o.SimpleAuthnSaml2AuthnCtxClass) {
    return nil, false
	}
	return o.SimpleAuthnSaml2AuthnCtxClass, true
}

// HasSimpleAuthnSaml2AuthnCtxClass returns a boolean if a field has been set.
func (o *DirectoryAuthenticationServiceDTO) HasSimpleAuthnSaml2AuthnCtxClass() bool {
	if o != nil && !isNil(o.SimpleAuthnSaml2AuthnCtxClass) {
		return true
	}

	return false
}

// SetSimpleAuthnSaml2AuthnCtxClass gets a reference to the given string and assigns it to the SimpleAuthnSaml2AuthnCtxClass field.
func (o *DirectoryAuthenticationServiceDTO) SetSimpleAuthnSaml2AuthnCtxClass(v string) {
	o.SimpleAuthnSaml2AuthnCtxClass = &v
}

// GetUsersCtxDN returns the UsersCtxDN field value if set, zero value otherwise.
func (o *DirectoryAuthenticationServiceDTO) GetUsersCtxDN() string {
	if o == nil || isNil(o.UsersCtxDN) {
		var ret string
		return ret
	}
	return *o.UsersCtxDN
}

// GetUsersCtxDNOk returns a tuple with the UsersCtxDN field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DirectoryAuthenticationServiceDTO) GetUsersCtxDNOk() (*string, bool) {
	if o == nil || isNil(o.UsersCtxDN) {
    return nil, false
	}
	return o.UsersCtxDN, true
}

// HasUsersCtxDN returns a boolean if a field has been set.
func (o *DirectoryAuthenticationServiceDTO) HasUsersCtxDN() bool {
	if o != nil && !isNil(o.UsersCtxDN) {
		return true
	}

	return false
}

// SetUsersCtxDN gets a reference to the given string and assigns it to the UsersCtxDN field.
func (o *DirectoryAuthenticationServiceDTO) SetUsersCtxDN(v string) {
	o.UsersCtxDN = &v
}

// GetX returns the X field value if set, zero value otherwise.
func (o *DirectoryAuthenticationServiceDTO) GetX() float64 {
	if o == nil || isNil(o.X) {
		var ret float64
		return ret
	}
	return *o.X
}

// GetXOk returns a tuple with the X field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DirectoryAuthenticationServiceDTO) GetXOk() (*float64, bool) {
	if o == nil || isNil(o.X) {
    return nil, false
	}
	return o.X, true
}

// HasX returns a boolean if a field has been set.
func (o *DirectoryAuthenticationServiceDTO) HasX() bool {
	if o != nil && !isNil(o.X) {
		return true
	}

	return false
}

// SetX gets a reference to the given float64 and assigns it to the X field.
func (o *DirectoryAuthenticationServiceDTO) SetX(v float64) {
	o.X = &v
}

// GetY returns the Y field value if set, zero value otherwise.
func (o *DirectoryAuthenticationServiceDTO) GetY() float64 {
	if o == nil || isNil(o.Y) {
		var ret float64
		return ret
	}
	return *o.Y
}

// GetYOk returns a tuple with the Y field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DirectoryAuthenticationServiceDTO) GetYOk() (*float64, bool) {
	if o == nil || isNil(o.Y) {
    return nil, false
	}
	return o.Y, true
}

// HasY returns a boolean if a field has been set.
func (o *DirectoryAuthenticationServiceDTO) HasY() bool {
	if o != nil && !isNil(o.Y) {
		return true
	}

	return false
}

// SetY gets a reference to the given float64 and assigns it to the Y field.
func (o *DirectoryAuthenticationServiceDTO) SetY(v float64) {
	o.Y = &v
}

func (o DirectoryAuthenticationServiceDTO) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if !isNil(o.CustomClass) {
		toSerialize["customClass"] = o.CustomClass
	}
	if !isNil(o.DelegatedAuthentications) {
		toSerialize["delegatedAuthentications"] = o.DelegatedAuthentications
	}
	if !isNil(o.Description) {
		toSerialize["description"] = o.Description
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
	if !isNil(o.IncludeOperationalAttributes) {
		toSerialize["includeOperationalAttributes"] = o.IncludeOperationalAttributes
	}
	if !isNil(o.InitialContextFactory) {
		toSerialize["initialContextFactory"] = o.InitialContextFactory
	}
	if !isNil(o.LdapSearchScope) {
		toSerialize["ldapSearchScope"] = o.LdapSearchScope
	}
	if !isNil(o.Name) {
		toSerialize["name"] = o.Name
	}
	if !isNil(o.PasswordPolicy) {
		toSerialize["passwordPolicy"] = o.PasswordPolicy
	}
	if !isNil(o.PerformDnSearch) {
		toSerialize["performDnSearch"] = o.PerformDnSearch
	}
	if !isNil(o.PrincipalUidAttributeID) {
		toSerialize["principalUidAttributeID"] = o.PrincipalUidAttributeID
	}
	if !isNil(o.ProviderUrl) {
		toSerialize["providerUrl"] = o.ProviderUrl
	}
	if !isNil(o.Referrals) {
		toSerialize["referrals"] = o.Referrals
	}
	if !isNil(o.SecurityAuthentication) {
		toSerialize["securityAuthentication"] = o.SecurityAuthentication
	}
	if !isNil(o.SecurityCredential) {
		toSerialize["securityCredential"] = o.SecurityCredential
	}
	if !isNil(o.SecurityPrincipal) {
		toSerialize["securityPrincipal"] = o.SecurityPrincipal
	}
	if !isNil(o.SimpleAuthnSaml2AuthnCtxClass) {
		toSerialize["simpleAuthnSaml2AuthnCtxClass"] = o.SimpleAuthnSaml2AuthnCtxClass
	}
	if !isNil(o.UsersCtxDN) {
		toSerialize["usersCtxDN"] = o.UsersCtxDN
	}
	if !isNil(o.X) {
		toSerialize["x"] = o.X
	}
	if !isNil(o.Y) {
		toSerialize["y"] = o.Y
	}

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return json.Marshal(toSerialize)
}

func (o *DirectoryAuthenticationServiceDTO) UnmarshalJSON(bytes []byte) (err error) {
	varDirectoryAuthenticationServiceDTO := _DirectoryAuthenticationServiceDTO{}

	if err = json.Unmarshal(bytes, &varDirectoryAuthenticationServiceDTO); err == nil {
		*o = DirectoryAuthenticationServiceDTO(varDirectoryAuthenticationServiceDTO)
	}

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(bytes, &additionalProperties); err == nil {
		delete(additionalProperties, "customClass")
		delete(additionalProperties, "delegatedAuthentications")
		delete(additionalProperties, "description")
		delete(additionalProperties, "displayName")
		delete(additionalProperties, "elementId")
		delete(additionalProperties, "id")
		delete(additionalProperties, "includeOperationalAttributes")
		delete(additionalProperties, "initialContextFactory")
		delete(additionalProperties, "ldapSearchScope")
		delete(additionalProperties, "name")
		delete(additionalProperties, "passwordPolicy")
		delete(additionalProperties, "performDnSearch")
		delete(additionalProperties, "principalUidAttributeID")
		delete(additionalProperties, "providerUrl")
		delete(additionalProperties, "referrals")
		delete(additionalProperties, "securityAuthentication")
		delete(additionalProperties, "securityCredential")
		delete(additionalProperties, "securityPrincipal")
		delete(additionalProperties, "simpleAuthnSaml2AuthnCtxClass")
		delete(additionalProperties, "usersCtxDN")
		delete(additionalProperties, "x")
		delete(additionalProperties, "y")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableDirectoryAuthenticationServiceDTO struct {
	value *DirectoryAuthenticationServiceDTO
	isSet bool
}

func (v NullableDirectoryAuthenticationServiceDTO) Get() *DirectoryAuthenticationServiceDTO {
	return v.value
}

func (v *NullableDirectoryAuthenticationServiceDTO) Set(val *DirectoryAuthenticationServiceDTO) {
	v.value = val
	v.isSet = true
}

func (v NullableDirectoryAuthenticationServiceDTO) IsSet() bool {
	return v.isSet
}

func (v *NullableDirectoryAuthenticationServiceDTO) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableDirectoryAuthenticationServiceDTO(val *DirectoryAuthenticationServiceDTO) *NullableDirectoryAuthenticationServiceDTO {
	return &NullableDirectoryAuthenticationServiceDTO{value: val, isSet: true}
}

func (v NullableDirectoryAuthenticationServiceDTO) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableDirectoryAuthenticationServiceDTO) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

